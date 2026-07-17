package nostr

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lnproxy/lnc"
	relay "github.com/lnproxy/lnproxy-relay"
)

type idempotencyLN struct {
	mu         sync.Mutex
	addCalls   int
	addErr     error
	addStarted chan struct{}
	addRelease chan struct{}
}

func (l *idempotencyLN) DecodeInvoice(string) (*lnc.DecodedInvoice, error) {
	return validDecodedInvoice(), nil
}

func (l *idempotencyLN) AddInvoice(lnc.InvoiceParameters) (string, error) {
	l.mu.Lock()
	l.addCalls++
	first := l.addCalls == 1
	l.mu.Unlock()
	if first && l.addStarted != nil {
		close(l.addStarted)
		<-l.addRelease
	}
	return "lnbc-proxy-invoice", l.addErr
}

func (l *idempotencyLN) WatchInvoice([]byte) (*lnc.InvoiceState, error) {
	return &lnc.InvoiceState{State: lnc.Canceled}, nil
}
func (l *idempotencyLN) CancelInvoice([]byte) error { return nil }
func (l *idempotencyLN) PayInvoice(lnc.PaymentParameters) ([]byte, error) {
	return nil, lnc.PaymentFailed
}
func (l *idempotencyLN) SettleInvoice([]byte) error { return nil }
func (l *idempotencyLN) EstimateRoutingFee(lnc.DecodedInvoice, uint64) (uint64, uint64, error) {
	return 1000, 144, nil
}

func (l *idempotencyLN) calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.addCalls
}

func TestServerDeduplicatesConcurrentRequestIDs(t *testing.T) {
	ln := &idempotencyLN{addStarted: make(chan struct{}), addRelease: make(chan struct{})}
	server := NewServer(relayForServerTest(ln), Offer{
		Features:         []string{FeatureWrapBolt11, FeatureRequestIDV1},
		MaxExpirySeconds: 3600,
	})
	req := Request{
		Method:    MethodWrap,
		RequestID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Invoice:   "lnbc1...",
		Wrap:      "bolt11",
	}

	responses := make(chan Response, 2)
	go func() { responses <- server.Wrap(req) }()
	<-ln.addStarted
	go func() { responses <- server.Wrap(req) }()
	close(ln.addRelease)

	for range 2 {
		resp := <-responses
		if resp.ProxyInvoice != "lnbc-proxy-invoice" || resp.RequestID != req.RequestID {
			t.Fatalf("unexpected response: %+v", resp)
		}
	}
	if got := ln.calls(); got != 1 {
		t.Fatalf("AddInvoice calls = %d, want 1", got)
	}
	server.Relay.WaitGroup.Wait()
}

func TestServerRejectsRequestIDReuseWithDifferentRequest(t *testing.T) {
	ln := &idempotencyLN{}
	server := NewServer(relayForServerTest(ln), Offer{Features: []string{FeatureWrapBolt11}})
	req := Request{
		Method:    MethodWrap,
		RequestID: strings.Repeat("a", 64),
		Invoice:   "lnbc1...",
		Wrap:      "bolt11",
	}
	first := server.Wrap(req)
	if first.ProxyInvoice == "" {
		t.Fatalf("first request failed: %+v", first)
	}
	req.Description = stringPointer("different")
	second := server.Wrap(req)
	if second.Status != "ERROR" || second.Reason != "request_id reused with different request" {
		t.Fatalf("unexpected conflict response: %+v", second)
	}
	if got := ln.calls(); got != 1 {
		t.Fatalf("AddInvoice calls = %d, want 1", got)
	}
	server.Relay.WaitGroup.Wait()
}

func TestServerRejectsInvalidRequestID(t *testing.T) {
	ln := &idempotencyLN{}
	server := NewServer(relayForServerTest(ln), Offer{Features: []string{FeatureWrapBolt11}})
	resp := server.Wrap(Request{Method: MethodWrap, RequestID: "not-an-id", Invoice: "lnbc1..."})
	if resp.Status != "ERROR" || resp.Reason != "invalid request_id" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got := ln.calls(); got != 0 {
		t.Fatalf("AddInvoice calls = %d, want 0", got)
	}
}

func TestServerRejectsMismatchedProviderPubkey(t *testing.T) {
	ln := &idempotencyLN{}
	provider := strings.Repeat("a", 64)
	server := NewServer(relayForServerTest(ln), Offer{Features: []string{FeatureWrapBolt11}}, provider)
	resp := server.Wrap(Request{
		Method:         MethodWrap,
		RequestID:      strings.Repeat("b", 64),
		ProviderPubkey: strings.Repeat("c", 64),
		Invoice:        "lnbc1...",
	})
	if resp.Status != "ERROR" || resp.Reason != "provider_pubkey mismatch" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got := ln.calls(); got != 0 {
		t.Fatalf("AddInvoice calls = %d, want 0", got)
	}
}

func TestServerDoesNotEvictUnexpiredRequestIDs(t *testing.T) {
	server := NewServer(relayForServerTest(&idempotencyLN{}), Offer{Features: []string{FeatureWrapBolt11}})
	ready := make(chan struct{})
	close(ready)
	expiresAt := server.now().Add(time.Hour)
	for i := range maxCachedRequests {
		id := fmt.Sprintf("%064x", i)
		server.requests[id] = &requestResult{
			fingerprint: "cached",
			response:    Response{RequestID: id, ProxyInvoice: "lnbc-cached"},
			ready:       ready,
			expiresAt:   expiresAt,
		}
	}

	newID := strings.Repeat("f", 64)
	resp := server.Wrap(Request{Method: MethodWrap, RequestID: newID, Invoice: "lnbc1..."})
	if resp.Status != "ERROR" || resp.Reason != "request cache full" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(server.requests) != maxCachedRequests {
		t.Fatalf("cache size = %d, want %d", len(server.requests), maxCachedRequests)
	}
	if _, ok := server.requests[fmt.Sprintf("%064x", 0)]; !ok {
		t.Fatal("unexpired cache entry was evicted")
	}
}

func TestServerExpiresSideEffectFreeErrorsQuickly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := NewServer(relayForServerTest(&idempotencyLN{}), Offer{Features: []string{FeatureWrapBolt11}})
	server.now = func() time.Time { return now }
	req := Request{
		Method:    MethodWrap,
		RequestID: strings.Repeat("a", 64),
		Invoice:   "lnbc1...",
		Wrap:      "bolt12",
	}
	server.Wrap(req)
	first := server.requests[req.RequestID]
	if got := first.expiresAt.Sub(now); got != errorCacheTTL {
		t.Fatalf("error cache TTL = %s, want %s", got, errorCacheTTL)
	}

	now = now.Add(errorCacheTTL + time.Second)
	server.Wrap(req)
	if server.requests[req.RequestID] == first {
		t.Fatal("expired error cache entry was reused")
	}
}

func TestServerRetainsUncertainAddInvoiceErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ln := &idempotencyLN{addErr: errors.New("add invoice response lost")}
	server := NewServer(relayForServerTest(ln), Offer{
		Features:         []string{FeatureWrapBolt11},
		MaxExpirySeconds: 3600,
	})
	server.now = func() time.Time { return now }
	req := Request{
		Method:    MethodWrap,
		RequestID: strings.Repeat("a", 64),
		Invoice:   "lnbc1...",
		Wrap:      "bolt11",
	}

	response := server.Wrap(req)
	if response.Status != "ERROR" || response.Reason != "internal error" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if got := server.requests[req.RequestID].expiresAt.Sub(now); got != server.cacheTTL {
		t.Fatalf("uncertain error cache TTL = %s, want %s", got, server.cacheTTL)
	}
}

func relayForServerTest(ln *idempotencyLN) *relay.Relay {
	return relay.NewRelay(ln)
}

func stringPointer(value string) *string { return &value }
