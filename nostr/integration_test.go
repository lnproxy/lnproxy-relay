//go:build integration

// Integration tests for the nostr transport against a real relay.
//
// Bring the relay up first:
//
//	docker compose -f docker-compose.test.yml up -d
//	LNPROXY_TEST_NOSTR_RELAY=ws://127.0.0.1:7777 go test -tags=integration ./nostr/...
//	docker compose -f docker-compose.test.yml down -v
//
// If LNPROXY_TEST_NOSTR_RELAY is unset the tests are skipped.
package nostr

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"

	relay "github.com/lnproxy/lnproxy-relay"
)

func relayURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("LNPROXY_TEST_NOSTR_RELAY")
	if url == "" {
		t.Skip("set LNPROXY_TEST_NOSTR_RELAY to run integration tests (see docker-compose.test.yml)")
	}
	return url
}

// TestIntegrationOfferAndWrap runs the provider transport against a real relay
// and performs a full client discovery + wrap round-trip over the wire.
func TestIntegrationOfferAndWrap(t *testing.T) {
	url := relayURL(t)
	relays := []string{url}

	r := relay.NewRelay(&mockLN{decoded: validDecodedInvoice()})
	id, err := LoadOrCreateIdentity(t.TempDir() + "/key")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	offer := Offer{
		BaseFeeMsat:   1000,
		FeePPM:        1000,
		MinAmountMsat: 1000,
		MaxAmountMsat: 1_000_000_000,
		MinRequestPoW: 8, // small but non-zero, exercises the gate over the wire
		Features:      []string{FeaturePayBolt11, FeatureWrapBolt11},
	}
	cfg := Config{
		SecretKey:         id.SecretKey,
		PublicKey:         id.PublicKey,
		Relays:            relays,
		Network:           Regtest,
		Offer:             offer,
		AnnouncePoWTarget: 8,
		OfferInterval:     time.Minute,
		RequestRateLimit:  10 * time.Millisecond,
	}
	pool := gonostr.NewSimplePool(context.Background())
	transport := NewTransport(cfg, pool, NewServer(r, offer))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)

	// 1. Confirm the offer is published and discoverable over the real relay.
	clientPool := gonostr.NewSimplePool(context.Background())
	discovered := waitForOffer(t, ctx, clientPool, relays, id.PublicKey, 15*time.Second)
	if discovered.Content == "" {
		t.Fatal("offer content empty")
	}
	var gotOffer Offer
	if err := json.Unmarshal([]byte(discovered.Content), &gotOffer); err != nil {
		t.Fatalf("offer json: %v", err)
	}
	if gotOffer.BaseFeeMsat != 1000 || gotOffer.MinRequestPoW != 8 {
		t.Fatalf("unexpected offer: %+v", gotOffer)
	}

	// 2. Send a real wrap request with proof of work and await the response.
	req := Request{Method: MethodWrap, Invoice: "lnbc1...", Wrap: "bolt11"}
	reqEvt := buildClientRequest(t, id.PublicKey, req, offer.MinRequestPoW)
	clientPK := reqEvt.Event.PubKey

	respCh := clientPool.SubscribeMany(ctx, relays, gonostr.Filter{
		Kinds: []int{KindResponse},
		Tags:  gonostr.TagMap{"p": []string{clientPK}, "e": []string{reqEvt.Event.ID}},
	})

	// Give the subscription a moment to register, then publish the request.
	time.Sleep(500 * time.Millisecond)
	for range clientPool.PublishMany(ctx, relays, *reqEvt.Event) {
	}

	resp := waitForResponse(t, ctx, respCh, 20*time.Second)
	convKey, err := nip44.GenerateConversationKey(clientPK, id.SecretKey)
	if err != nil {
		t.Fatalf("conv key: %v", err)
	}
	plaintext, err := nip44.Decrypt(resp.Content, convKey)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var parsed Response
	if err := json.Unmarshal([]byte(plaintext), &parsed); err != nil {
		t.Fatalf("response json: %v", err)
	}
	if parsed.ProxyInvoice != "lnbc-proxy-invoice" {
		t.Fatalf("unexpected response: %+v", parsed)
	}

	r.WaitGroup.Wait()
}

// TestIntegrationAnonymousProviderOffer covers an anonymous provider (no node
// attestation) that proves its identity with the optional identity proof of
// work instead. It publishes such an offer over a real relay and checks that a
// client can rediscover it and verify the anonymous proof of work.
func TestIntegrationAnonymousProviderOffer(t *testing.T) {
	url := relayURL(t)
	relays := []string{url}

	r := relay.NewRelay(&mockLN{decoded: validDecodedInvoice()})
	id, err := LoadOrCreateIdentity(t.TempDir() + "/key")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	// Mine a small identity proof of work bound to this nostr pubkey.
	const target = 8
	nonce, bits, err := MineAnnouncePoW(id.PublicKey, target, 1, 0)
	if err != nil {
		t.Fatalf("mine identity pow: %v", err)
	}
	if bits < target {
		t.Fatalf("mined %d bits, want >= %d", bits, target)
	}

	offer := Offer{
		BaseFeeMsat:   500,
		FeePPM:        500,
		MinAmountMsat: 1000,
		MaxAmountMsat: 1_000_000_000,
		MinRequestPoW: 0,
		Features:      []string{FeaturePayBolt11, FeatureWrapBolt11},
		PoWNonce:      "0x" + strconv.FormatUint(nonce, 16),
		// No NodePubkey / NodeSig: this provider is anonymous.
	}
	cfg := Config{
		SecretKey:         id.SecretKey,
		PublicKey:         id.PublicKey,
		Relays:            relays,
		Network:           Regtest,
		Offer:             offer,
		AnnouncePoWTarget: 8,
		OfferInterval:     time.Minute,
		RequestRateLimit:  10 * time.Millisecond,
	}
	pool := gonostr.NewSimplePool(context.Background())
	transport := NewTransport(cfg, pool, NewServer(r, offer))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.Run(ctx)

	clientPool := gonostr.NewSimplePool(context.Background())
	discovered := waitForOffer(t, ctx, clientPool, relays, id.PublicKey, 15*time.Second)

	var gotOffer Offer
	if err := json.Unmarshal([]byte(discovered.Content), &gotOffer); err != nil {
		t.Fatalf("offer json: %v", err)
	}
	if gotOffer.NodePubkey != "" || gotOffer.NodeSig != "" {
		t.Fatalf("expected anonymous offer, got node attestation: %+v", gotOffer)
	}
	if gotOffer.PoWNonce == "" {
		t.Fatal("anonymous offer missing pow_nonce")
	}

	// A client verifies the anonymous identity proof of work.
	parsedNonce, err := strconv.ParseUint(gotOffer.PoWNonce[2:], 16, 64)
	if err != nil {
		t.Fatalf("parse pow_nonce: %v", err)
	}
	verifiedBits, err := AnnouncePoWBits(discovered.PubKey, parsedNonce)
	if err != nil {
		t.Fatalf("verify identity pow: %v", err)
	}
	if verifiedBits < target {
		t.Fatalf("anonymous identity pow verified at %d bits, want >= %d", verifiedBits, target)
	}
}

func waitForOffer(t *testing.T, ctx context.Context, pool *gonostr.SimplePool, relays []string, pubkey string, timeout time.Duration) *gonostr.Event {
	t.Helper()
	sub := pool.SubscribeMany(ctx, relays, gonostr.Filter{
		Kinds: []int{KindOffer},
		Tags:  gonostr.TagMap{"d": []string{ProtocolVersion}},
	})
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-sub:
			if !ok {
				t.Fatal("offer subscription closed")
			}
			if ev.Event != nil && ev.Event.PubKey == pubkey {
				return ev.Event
			}
		case <-deadline:
			t.Fatal("timed out waiting for offer over relay")
			return nil
		}
	}
}

func waitForResponse(t *testing.T, ctx context.Context, ch chan gonostr.RelayEvent, timeout time.Duration) *gonostr.Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("response subscription closed")
			}
			if ev.Event != nil {
				return ev.Event
			}
		case <-deadline:
			t.Fatal("timed out waiting for wrap response over relay")
			return nil
		}
	}
}
