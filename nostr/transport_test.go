package nostr

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
	"github.com/nbd-wtf/go-nostr/nip44"

	"github.com/lnproxy/lnc"
	relay "github.com/lnproxy/lnproxy-relay"
)

// mockLN is a minimal lnc.LN that lets a real relay.Relay run end-to-end in
// tests without a node. The circuit goroutine started by OpenCircuit watches
// the invoice; we return Canceled immediately so it exits cleanly.
type mockLN struct {
	decoded *lnc.DecodedInvoice
	addErr  error
}

func (m *mockLN) DecodeInvoice(string) (*lnc.DecodedInvoice, error) {
	return m.decoded, nil
}
func (m *mockLN) AddInvoice(lnc.InvoiceParameters) (string, error) {
	if m.addErr != nil {
		return "", m.addErr
	}
	return "lnbc-proxy-invoice", nil
}
func (m *mockLN) WatchInvoice([]byte) (*lnc.InvoiceState, error) {
	return &lnc.InvoiceState{State: lnc.Canceled}, nil
}
func (m *mockLN) CancelInvoice([]byte) error { return nil }
func (m *mockLN) PayInvoice(lnc.PaymentParameters) ([]byte, error) {
	return nil, lnc.PaymentFailed
}
func (m *mockLN) SettleInvoice([]byte) error { return nil }
func (m *mockLN) EstimateRoutingFee(lnc.DecodedInvoice, uint64) (uint64, uint64, error) {
	return 1000, 144, nil
}

func validDecodedInvoice() *lnc.DecodedInvoice {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	return &lnc.DecodedInvoice{
		PaymentHash: hex.EncodeToString(hash),
		Timestamp:   uint64(time.Now().Unix()),
		Expiry:      3600,
		Description: "test",
		NumMsat:     1_000_000,
		CltvExpiry:  40,
		Destination: "02deadbeef",
	}
}

// fakePool implements Pool for tests: SubscribeMany returns a channel the test
// feeds, PublishMany records published events.
type fakePool struct {
	incoming        chan gonostr.RelayEvent
	published       chan *gonostr.Event
	publishedURLs   chan []string
	publishMu       sync.Mutex
	publishFailures map[string]bool
}

type countingWrapHandler struct {
	mu    sync.Mutex
	calls int
}

func (h *countingWrapHandler) Wrap(Request) Response {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	return Response{ProxyInvoice: "lnbc-proxy-invoice"}
}

func (h *countingWrapHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func newFakePool() *fakePool {
	return &fakePool{
		incoming:        make(chan gonostr.RelayEvent, 4),
		published:       make(chan *gonostr.Event, 16),
		publishedURLs:   make(chan []string, 16),
		publishFailures: make(map[string]bool),
	}
}

func (p *fakePool) SubscribeMany(ctx context.Context, urls []string, filter gonostr.Filter, opts ...gonostr.SubscriptionOption) chan gonostr.RelayEvent {
	return p.incoming
}

func (p *fakePool) PublishMany(ctx context.Context, urls []string, evt gonostr.Event) chan gonostr.PublishResult {
	e := evt
	p.published <- &e
	p.publishedURLs <- append([]string(nil), urls...)
	ch := make(chan gonostr.PublishResult, len(urls))
	for _, url := range urls {
		result := gonostr.PublishResult{RelayURL: url}
		p.publishMu.Lock()
		if p.publishFailures[url] {
			result.Error = errors.New("publish failed")
		}
		p.publishMu.Unlock()
		ch <- result
	}
	close(ch)
	return ch
}

func (p *fakePool) setPublishFailure(url string) {
	p.publishMu.Lock()
	defer p.publishMu.Unlock()
	p.publishFailures[url] = true
}

func TestTransportRepliesOnlyThroughSourceRelay(t *testing.T) {
	handler := &countingWrapHandler{}
	transport, pool, id := newTestTransport(t, handler)
	transport.cfg.Relays = []string{"wss://one.example", "wss://two.example"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)
	waitForPublished(t, pool, KindOffer)
	<-pool.publishedURLs

	event := buildClientRequest(t, id.PublicKey, Request{Method: MethodWrap, Invoice: "lnbc1..."}, 0)
	event.Relay = &gonostr.Relay{URL: "wss://two.example"}
	pool.incoming <- event
	waitForPublished(t, pool, KindResponse)
	if got := <-pool.publishedURLs; len(got) != 1 || got[0] != "wss://two.example" {
		t.Fatalf("response relays = %v, want source relay only", got)
	}
}

func TestTransportFallsBackAfterSourceRelayPublishFailure(t *testing.T) {
	handler := &countingWrapHandler{}
	transport, pool, id := newTestTransport(t, handler)
	transport.cfg.Relays = []string{"wss://one.example", "wss://two.example"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)
	waitForPublished(t, pool, KindOffer)
	<-pool.publishedURLs
	pool.setPublishFailure("wss://one.example")

	event := buildClientRequest(t, id.PublicKey, Request{Method: MethodWrap, Invoice: "lnbc1..."}, 0)
	event.Relay = &gonostr.Relay{URL: "wss://one.example"}
	pool.incoming <- event
	waitForPublished(t, pool, KindResponse)
	if got := <-pool.publishedURLs; len(got) != 1 || got[0] != "wss://one.example" {
		t.Fatalf("first response relays = %v, want source", got)
	}
	waitForPublished(t, pool, KindResponse)
	if got := <-pool.publishedURLs; len(got) != 1 || got[0] != "wss://two.example" {
		t.Fatalf("fallback response relays = %v, want alternate", got)
	}
}

func TestTransportRejectsOversizedAndDuplicateRequestTags(t *testing.T) {
	transport, _, id := newTestTransport(t, &countingWrapHandler{})
	request := Request{Method: MethodWrap, Invoice: "lnbc1..."}

	oversized := buildClientRequest(t, id.PublicKey, request, 0)
	oversized.Tags = append(oversized.Tags, gonostr.Tag{"x", strings.Repeat("a", maxRequestTagBytes)})
	if transport.admitRequest(oversized.Event) {
		t.Fatal("oversized request tags were admitted")
	}

	duplicateNonce := buildClientRequest(t, id.PublicKey, request, 0)
	duplicateNonce.Tags = append(duplicateNonce.Tags, gonostr.Tag{"nonce", "1", "0"})
	if transport.admitRequest(duplicateNonce.Event) {
		t.Fatal("duplicate nonce tags were admitted")
	}
}

func TestOfferUsesClientReachableRelayAliases(t *testing.T) {
	transport, _, _ := newTestTransport(t, &countingWrapHandler{})
	transport.cfg.Relays = []string{"ws://relay.internal:8080"}
	transport.cfg.AdvertisedRelays = []string{"wss://relay.example"}
	transport.cfg.AnnouncePoWTarget = 0

	event, err := transport.buildOfferEvent(context.Background())
	if err != nil {
		t.Fatalf("build offer: %v", err)
	}
	var offer Offer
	if err := json.Unmarshal([]byte(event.Content), &offer); err != nil {
		t.Fatalf("parse offer: %v", err)
	}
	if len(offer.Relays) != 1 || offer.Relays[0] != "wss://relay.example" {
		t.Fatalf("advertised relays = %v, want client-reachable alias", offer.Relays)
	}
}

func newTestTransport(t *testing.T, handler WrapHandler) (*Transport, *fakePool, Identity) {
	t.Helper()
	id, err := LoadOrCreateIdentity(t.TempDir() + "/key")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pool := newFakePool()
	cfg := Config{
		SecretKey:         id.SecretKey,
		PublicKey:         id.PublicKey,
		Relays:            []string{"wss://example"},
		Network:           Regtest,
		Offer:             Offer{MinRequestPoW: 0, Features: []string{FeatureWrapBolt11}},
		AnnouncePoWTarget: -1,
		RequestRateLimit:  time.Millisecond,
	}
	transport := NewTransport(cfg, pool, handler)
	// Response PoW is production transport policy, not behavior under test here.
	// Disabling it keeps race-detector runs deterministic on constrained CI hosts.
	transport.responsePoWTarget = 0
	return transport, pool, id
}

// buildClientRequest builds a signed, encrypted kind 21821 request event from a
// fresh client key to the provider.
func buildClientRequest(t *testing.T, providerPub string, req Request, powTarget int) gonostr.RelayEvent {
	t.Helper()
	clientSK := gonostr.GeneratePrivateKey()
	clientPK, err := gonostr.GetPublicKey(clientSK)
	if err != nil {
		t.Fatalf("client pubkey: %v", err)
	}
	convKey, err := nip44.GenerateConversationKey(providerPub, clientSK)
	if err != nil {
		t.Fatalf("conv key: %v", err)
	}
	plaintext, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal req: %v", err)
	}
	ciphertext, err := nip44.Encrypt(string(plaintext), convKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	evt := gonostr.Event{
		PubKey:    clientPK,
		CreatedAt: gonostr.Now(),
		Kind:      KindRequest,
		Tags:      gonostr.Tags{{"p", providerPub}},
		Content:   ciphertext,
	}
	if powTarget > 0 {
		nonceTag, err := nip13.DoWork(context.Background(), evt, powTarget)
		if err != nil {
			t.Fatalf("client pow: %v", err)
		}
		evt.Tags = append(evt.Tags, nonceTag)
	} else {
		evt.Tags = append(evt.Tags, gonostr.Tag{"nonce", "0", "0"})
	}
	if err := evt.Sign(clientSK); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return gonostr.RelayEvent{Event: &evt}
}

// decryptResponse decrypts a captured response event with the provider pubkey
// using the client's view: it derives the conversation key from the provider
// pubkey and the client secret. Here we cheat by re-deriving with the provider
// secret, which yields the same shared key.
func decryptResponse(t *testing.T, providerSK string, clientPub string, evt *gonostr.Event) Response {
	t.Helper()
	convKey, err := nip44.GenerateConversationKey(clientPub, providerSK)
	if err != nil {
		t.Fatalf("conv key: %v", err)
	}
	plaintext, err := nip44.Decrypt(evt.Content, convKey)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	var resp Response
	if err := json.Unmarshal([]byte(plaintext), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

func TestTransportWrapRoundTrip(t *testing.T) {
	r := relay.NewRelay(&mockLN{decoded: validDecodedInvoice()})
	offer := Offer{MinRequestPoW: 0, Features: []string{FeatureWrapBolt11}}
	server := NewServer(r, offer)

	transport, pool, id := newTestTransport(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)

	// drain the offer publication
	waitForPublished(t, pool, KindOffer)

	req := Request{Method: MethodWrap, Invoice: "lnbc1...", Wrap: "bolt11"}
	reqEvt := buildClientRequest(t, id.PublicKey, req, 0)
	pool.incoming <- reqEvt

	respEvt := waitForPublished(t, pool, KindResponse)
	resp := decryptResponse(t, id.SecretKey, reqEvt.PubKey, respEvt)
	if resp.ProxyInvoice != "lnbc-proxy-invoice" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	// response must reference the request
	if respEvt.Tags.GetFirst([]string{"e"}) == nil {
		t.Fatal("response missing e tag")
	}

	r.WaitGroup.Wait()
}

func TestTransportRejectsUnsupportedWrap(t *testing.T) {
	r := relay.NewRelay(&mockLN{decoded: validDecodedInvoice()})
	offer := Offer{MinRequestPoW: 0, Features: []string{FeatureWrapBolt11}}
	server := NewServer(r, offer)
	transport, pool, id := newTestTransport(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)
	waitForPublished(t, pool, KindOffer)

	req := Request{Method: MethodWrap, Invoice: "lnbc1...", Wrap: "bolt12"}
	reqEvt := buildClientRequest(t, id.PublicKey, req, 0)
	pool.incoming <- reqEvt

	respEvt := waitForPublished(t, pool, KindResponse)
	resp := decryptResponse(t, id.SecretKey, reqEvt.PubKey, respEvt)
	if resp.Status != "ERROR" {
		t.Fatalf("expected ERROR, got %+v", resp)
	}
}

func TestTransportDropsLowPoWRequest(t *testing.T) {
	r := relay.NewRelay(&mockLN{decoded: validDecodedInvoice()})
	offer := Offer{MinRequestPoW: 24, Features: []string{FeatureWrapBolt11}}
	server := NewServer(r, offer)
	transport, pool, id := newTestTransport(t, server)
	transport.cfg.Offer.MinRequestPoW = 24

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)
	waitForPublished(t, pool, KindOffer)

	// Request with no proof of work must be dropped (no response published).
	req := Request{Method: MethodWrap, Invoice: "lnbc1...", Wrap: "bolt11"}
	reqEvt := buildClientRequest(t, id.PublicKey, req, 0)
	pool.incoming <- reqEvt

	select {
	case evt := <-pool.published:
		if evt.Kind == KindResponse {
			t.Fatal("expected low-pow request to be dropped, got a response")
		}
	case <-time.After(200 * time.Millisecond):
		// good: nothing published
	}
}

func TestTransportLowPoWRequestsDoNotDelayValidRequest(t *testing.T) {
	handler := &countingWrapHandler{}
	transport, pool, id := newTestTransport(t, handler)
	transport.cfg.Offer.MinRequestPoW = 4
	transport.cfg.RequestRateLimit = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)
	waitForPublished(t, pool, KindOffer)

	request := Request{Method: MethodWrap, Invoice: "lnbc1...", Wrap: "bolt11"}
	for range 3 {
		pool.incoming <- buildClientRequest(t, id.PublicKey, request, 0)
	}
	pool.incoming <- buildClientRequest(t, id.PublicKey, request, 4)

	select {
	case event := <-pool.published:
		if event.Kind != KindResponse {
			t.Fatalf("published kind = %d, want response", event.Kind)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("valid request was delayed by rejected low-pow traffic")
	}
	if got := handler.count(); got != 1 {
		t.Fatalf("handler calls = %d, want 1", got)
	}
}

func TestTransportDeduplicatesRequestEvents(t *testing.T) {
	handler := &countingWrapHandler{}
	transport, pool, id := newTestTransport(t, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)
	waitForPublished(t, pool, KindOffer)

	event := buildClientRequest(t, id.PublicKey, Request{Method: MethodWrap, Invoice: "lnbc1..."}, 0)
	pool.incoming <- event
	pool.incoming <- event
	waitForPublished(t, pool, KindResponse)
	time.Sleep(50 * time.Millisecond)
	if got := handler.count(); got != 1 {
		t.Fatalf("handler calls = %d, want 1", got)
	}
}

func TestTransportRejectsStaleAndMisaddressedRequests(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T, transport *Transport, id Identity) gonostr.RelayEvent
	}{
		{
			name: "stale",
			build: func(t *testing.T, transport *Transport, id Identity) gonostr.RelayEvent {
				transport.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
				return buildClientRequest(t, id.PublicKey, Request{Method: MethodWrap, Invoice: "lnbc1..."}, 0)
			},
		},
		{
			name: "misaddressed",
			build: func(t *testing.T, _ *Transport, _ Identity) gonostr.RelayEvent {
				otherSK := gonostr.GeneratePrivateKey()
				otherPK, err := gonostr.GetPublicKey(otherSK)
				if err != nil {
					t.Fatalf("other pubkey: %v", err)
				}
				return buildClientRequest(t, otherPK, Request{Method: MethodWrap, Invoice: "lnbc1..."}, 0)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &countingWrapHandler{}
			transport, pool, id := newTestTransport(t, handler)
			event := test.build(t, transport, id)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go transport.Run(ctx)
			waitForPublished(t, pool, KindOffer)
			pool.incoming <- event

			select {
			case event := <-pool.published:
				if event.Kind == KindResponse {
					t.Fatal("unexpected response to invalid request")
				}
			case <-time.After(200 * time.Millisecond):
			}
			if got := handler.count(); got != 0 {
				t.Fatalf("handler calls = %d, want 0", got)
			}
		})
	}
}

func waitForPublished(t *testing.T, pool *fakePool, kind int) *gonostr.Event {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case evt := <-pool.published:
			if evt.Kind == kind {
				return evt
			}
		case <-deadline:
			t.Fatalf("timed out waiting for published event kind %d", kind)
			return nil
		}
	}
}

// sanity: Server maps client-facing relay errors through.
func TestServerClientFacingError(t *testing.T) {
	bad := validDecodedInvoice()
	bad.NumMsat = 0 // triggers "zero amount invoices cannot be relayed trustlessly"
	r := relay.NewRelay(&mockLN{decoded: bad})
	server := NewServer(r, Offer{Features: []string{FeatureWrapBolt11}})

	resp := server.Wrap(Request{Method: MethodWrap, Invoice: "x", Wrap: "bolt11"})
	if resp.Status != "ERROR" {
		t.Fatalf("expected ERROR, got %+v", resp)
	}
	if resp.Reason == "" {
		t.Fatal("expected a client-facing reason, got empty")
	}
}

// TestTransportServesRegardlessOfAnnouncePoW documents the threat model: the
// provider gates incoming requests on the client's request proof of work, but
// does not gate on its own announcement proof of work. A request meeting
// MinRequestPoW is served even when AnnouncePoWTarget is high.
func TestTransportServesRegardlessOfAnnouncePoW(t *testing.T) {
	r := relay.NewRelay(&mockLN{decoded: validDecodedInvoice()})
	offer := Offer{MinRequestPoW: 0, Features: []string{FeatureWrapBolt11}}
	server := NewServer(r, offer)
	transport, pool, id := newTestTransport(t, server)
	// A non-trivial announcement target must not affect request handling.
	transport.cfg.AnnouncePoWTarget = 16

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)
	waitForPublished(t, pool, KindOffer)

	// Client request carries no proof of work; MinRequestPoW is 0, so it is served.
	req := Request{Method: MethodWrap, Invoice: "lnbc1...", Wrap: "bolt11"}
	reqEvt := buildClientRequest(t, id.PublicKey, req, 0)
	pool.incoming <- reqEvt

	respEvt := waitForPublished(t, pool, KindResponse)
	resp := decryptResponse(t, id.SecretKey, reqEvt.PubKey, respEvt)
	if resp.ProxyInvoice != "lnbc-proxy-invoice" {
		t.Fatalf("expected wrap to succeed, got %+v", resp)
	}
	r.WaitGroup.Wait()
}
