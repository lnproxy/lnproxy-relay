package nostr

import (
	"encoding/json"
	"errors"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	relay "github.com/lnproxy/lnproxy-relay"
)

// Server implements WrapHandler by driving a *relay.Relay. It checks feature
// negotiation and maps the relay's client-facing and internal errors to the
// base protocol error format.
type Server struct {
	Relay *relay.Relay
	// Offer is consulted for advertised features so unsupported wrap formats
	// are rejected before touching the node.
	Offer Offer
	// ProviderPubkey binds direct requests to the identity that advertised the
	// endpoint. It prevents a malicious offer from reflecting work at a victim.
	ProviderPubkey string

	mu       sync.Mutex
	requests map[string]*requestResult
	cacheTTL time.Duration
	now      func() time.Time
}

const (
	maxCachedRequests = 4096
	errorCacheTTL     = time.Minute
)

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type requestResult struct {
	fingerprint string
	response    Response
	ready       chan struct{}
	expiresAt   time.Time
}

// NewServer constructs a Server.
func NewServer(r *relay.Relay, offer Offer, providerPubkey ...string) *Server {
	cacheTTL := time.Duration(offer.MaxExpirySeconds) * time.Second
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}
	server := &Server{
		Relay:    r,
		Offer:    offer,
		requests: make(map[string]*requestResult),
		cacheTTL: cacheTTL,
		now:      time.Now,
	}
	if len(providerPubkey) > 0 {
		server.ProviderPubkey = providerPubkey[0]
	}
	return server
}

// Wrap validates the requested output format, opens a circuit, and returns the
// proxy invoice or an error response.
func (s *Server) Wrap(req Request) Response {
	if s.ProviderPubkey != "" && req.ProviderPubkey != s.ProviderPubkey {
		return Response{RequestID: req.RequestID, Status: "ERROR", Reason: "provider_pubkey mismatch"}
	}
	if req.RequestID == "" {
		response, _ := s.wrap(req)
		return response
	}
	if !requestIDPattern.MatchString(req.RequestID) {
		return Response{RequestID: req.RequestID, Status: "ERROR", Reason: "invalid request_id"}
	}

	fingerprint, err := requestFingerprint(req)
	if err != nil {
		return Response{RequestID: req.RequestID, Status: "ERROR", Reason: "invalid request"}
	}

	now := s.now()
	s.mu.Lock()
	s.pruneLocked(now)
	if existing, ok := s.requests[req.RequestID]; ok {
		if existing.fingerprint != fingerprint {
			s.mu.Unlock()
			return Response{RequestID: req.RequestID, Status: "ERROR", Reason: "request_id reused with different request"}
		}
		ready := existing.ready
		s.mu.Unlock()
		<-ready
		return existing.response
	}
	if len(s.requests) >= maxCachedRequests {
		s.mu.Unlock()
		return Response{RequestID: req.RequestID, Status: "ERROR", Reason: "request cache full"}
	}
	result := &requestResult{
		fingerprint: fingerprint,
		ready:       make(chan struct{}),
	}
	s.requests[req.RequestID] = result
	s.mu.Unlock()

	response, durable := s.wrap(req)
	response.RequestID = req.RequestID

	s.mu.Lock()
	result.response = response
	ttl := s.cacheTTL
	if !durable && errorCacheTTL < ttl {
		ttl = errorCacheTTL
	}
	result.expiresAt = s.now().Add(ttl)
	close(result.ready)
	s.mu.Unlock()
	return response
}

func (s *Server) wrap(req Request) (Response, bool) {
	if req.Method != "" && req.Method != MethodWrap {
		return errorResponse("unsupported method"), false
	}
	feature := WrapFeature(req.Wrap)
	if !s.Offer.HasFeature(feature) {
		return errorResponse("unsupported wrap format: " + req.Wrap), false
	}

	proxyInvoice, err := s.Relay.OpenCircuit(req.ProxyParameters())
	if err == nil {
		return Response{ProxyInvoice: proxyInvoice}, true
	}
	if isClientFacing(err) {
		return errorResponse(strings.TrimSpace(err.Error())), relay.CircuitMayBeOpen(err)
	}
	log.Println("lnproxy: internal error for request:", err)
	return errorResponse("internal error"), relay.CircuitMayBeOpen(err)
}

func requestFingerprint(req Request) (string, error) {
	req.RequestID = ""
	b, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *Server) pruneLocked(now time.Time) {
	for id, result := range s.requests {
		if !result.expiresAt.IsZero() && !result.expiresAt.After(now) {
			delete(s.requests, id)
		}
	}
}

// isClientFacing reports whether err is a relay client-facing error, whose
// message is safe to return to the requester.
func isClientFacing(err error) bool {
	// relay.ClientFacing is an empty-message sentinel joined into client-facing
	// errors; errors.Is matches it.
	return errors.Is(err, relay.ClientFacing)
}
