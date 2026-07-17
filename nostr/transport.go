package nostr

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"sync"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// WrapHandler turns a decrypted request into a response. It is satisfied by
// *Server (which calls relay.Relay.OpenCircuit) and is an interface so tests
// can substitute a fake.
type WrapHandler interface {
	Wrap(req Request) Response
}

// Config configures a provider Transport.
type Config struct {
	// SecretKey is the provider's persistent nostr private key (hex).
	SecretKey string
	// PublicKey is the corresponding x-only public key (hex).
	PublicKey string
	// Relays is the set of nostr relay URLs to publish offers to and listen on.
	Relays []string
	// AdvertisedRelays optionally contains client-reachable aliases for Relays.
	// It is useful when the provider reaches a relay through an internal address.
	AdvertisedRelays []string
	// Network is the bitcoin network this provider serves.
	Network Network
	// Offer is the advertisement content (fees, limits, features, optional
	// attestation and identity proof of work). Relays is overwritten with
	// Config.Relays at publish time.
	Offer Offer
	// AnnouncePoWTarget is the NIP-13 difficulty mined into each offer event.
	AnnouncePoWTarget int
	// OfferInterval is how often offers are re-published.
	OfferInterval time.Duration
	// MaxQueuedRequests bounds the in-flight request queue; excess requests are
	// dropped (denial-of-service protection).
	MaxQueuedRequests int
	// RequestRateLimit is the minimum delay between dequeuing requests.
	RequestRateLimit time.Duration
}

// withDefaults returns a copy of c with sane defaults filled in.
func (c Config) withDefaults() Config {
	if c.AnnouncePoWTarget == 0 {
		c.AnnouncePoWTarget = 20
	}
	if c.OfferInterval == 0 {
		c.OfferInterval = 10 * time.Minute
	}
	if c.MaxQueuedRequests == 0 {
		c.MaxQueuedRequests = 5
	}
	if c.RequestRateLimit == 0 {
		c.RequestRateLimit = 5 * time.Second
	}
	return c
}

// Pool is the subset of *gonostr.SimplePool used by Transport, extracted as an
// interface for testing.
type Pool interface {
	SubscribeMany(ctx context.Context, urls []string, filter gonostr.Filter, opts ...gonostr.SubscriptionOption) chan gonostr.RelayEvent
	PublishMany(ctx context.Context, urls []string, evt gonostr.Event) chan gonostr.PublishResult
}

// Transport publishes provider offers and serves encrypted wrap requests over
// nostr. It is created with NewTransport and driven with Run.
type Transport struct {
	cfg               Config
	pool              Pool
	handler           WrapHandler
	responsePoWTarget int
	seenMu            sync.Mutex
	seenRequests      map[string]time.Time
	now               func() time.Time
}

const (
	requestFreshness   = 5 * time.Minute
	requestFutureSkew  = time.Minute
	maxSeenRequests    = 4096
	maxRequestContent  = 128 << 10
	maxRequestTags     = 16
	maxRequestTagBytes = 4 << 10
	maxRequestTagItems = 8
)

// NewTransport constructs a Transport. pool is usually a *gonostr.SimplePool.
func NewTransport(cfg Config, pool Pool, handler WrapHandler) *Transport {
	return &Transport{
		cfg:               cfg.withDefaults(),
		pool:              pool,
		handler:           handler,
		responsePoWTarget: 20,
		seenRequests:      make(map[string]time.Time),
		now:               time.Now,
	}
}

// buildOfferEvent constructs and signs a kind 38421 offer event for the current
// configuration, mining the announcement proof of work.
func (t *Transport) buildOfferEvent(ctx context.Context) (*gonostr.Event, error) {
	offer := t.cfg.Offer
	offer.Relays = t.cfg.AdvertisedRelays
	if len(offer.Relays) == 0 {
		offer.Relays = t.cfg.Relays
	}
	content, err := json.Marshal(offer)
	if err != nil {
		return nil, err
	}
	expiration := time.Now().Add(t.cfg.OfferInterval + time.Minute).Unix()
	evt := gonostr.Event{
		PubKey:    t.cfg.PublicKey,
		CreatedAt: gonostr.Now(),
		Kind:      KindOffer,
		Tags: gonostr.Tags{
			{"d", ProtocolVersion},
			{"n", string(t.cfg.Network)},
			{"expiration", strconv.FormatInt(expiration, 10)},
		},
		Content: string(content),
	}
	if t.cfg.AnnouncePoWTarget > 0 {
		nonceTag, err := nip13.DoWork(ctx, evt, t.cfg.AnnouncePoWTarget)
		if err != nil {
			return nil, err
		}
		evt.Tags = append(evt.Tags, nonceTag)
	}
	if err := evt.Sign(t.cfg.SecretKey); err != nil {
		return nil, err
	}
	return &evt, nil
}

// publishOffer mines and broadcasts one offer event.
func (t *Transport) publishOffer(ctx context.Context) error {
	evt, err := t.buildOfferEvent(ctx)
	if err != nil {
		return err
	}
	results := t.pool.PublishMany(ctx, t.cfg.Relays, *evt)
	successes := 0
	for result := range results {
		if result.Error != nil {
			log.Printf("nostr: offer publish to %s failed: %v", result.RelayURL, result.Error)
			continue
		}
		successes++
	}
	if successes == 0 && len(t.cfg.Relays) > 0 {
		return errors.New("nostr: offer publication failed on every relay")
	}
	log.Printf("nostr: published offer %s to %d relays", evt.ID, successes)
	return nil
}

// Run publishes offers periodically and serves incoming requests until ctx is
// cancelled. It blocks.
func (t *Transport) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerDone := make(chan struct{})
	queue := make(chan gonostr.RelayEvent, t.cfg.MaxQueuedRequests)
	go func() {
		defer close(workerDone)
		t.serveQueue(runCtx, queue)
	}()
	defer func() {
		cancel()
		<-workerDone
	}()

	if err := t.publishOffer(runCtx); err != nil {
		log.Println("nostr: initial offer publish error:", err)
	}

	since := gonostr.Timestamp(t.now().Add(-requestFreshness).Unix())
	sub := t.pool.SubscribeMany(runCtx, t.cfg.Relays, gonostr.Filter{
		Kinds: []int{KindRequest},
		Tags:  gonostr.TagMap{"p": []string{t.cfg.PublicKey}},
		Since: &since,
	})

	ticker := time.NewTicker(t.cfg.OfferInterval)
	defer ticker.Stop()

	for {
		select {
		case <-runCtx.Done():
			return runCtx.Err()
		case <-ticker.C:
			if err := t.publishOffer(runCtx); err != nil {
				log.Println("nostr: offer publish error:", err)
			}
		case ev, ok := <-sub:
			if !ok {
				return errors.New("nostr: subscription closed")
			}
			if ev.Event == nil {
				continue
			}
			if !t.admitRequest(ev.Event) {
				continue
			}
			select {
			case queue <- ev:
			default:
				log.Println("nostr: request queue full, dropping request", ev.Event.ID)
			}
		}
	}
}

// serveQueue processes queued requests one at a time, rate limited.
func (t *Transport) serveQueue(ctx context.Context, queue chan gonostr.RelayEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-queue:
			t.handleRequest(ctx, ev)
			select {
			case <-ctx.Done():
				return
			case <-time.After(t.cfg.RequestRateLimit):
			}
		}
	}
}

// handleRequest validates, decrypts, processes and replies to a single request
// event.
//
// A provider only needs to validate the requests reaching it: it checks the
// client's signature and that the client met the advertised request proof of
// work (MinRequestPoW), which is the denial-of-service protection. It does not
// verify its own announcement proof of work, nor any other provider's offer or
// proof of work; ranking providers by proof of work and attestation is purely a
// client concern.
func (t *Transport) admitRequest(evt *gonostr.Event) bool {
	if !requestEnvelopeWithinBounds(evt) {
		log.Println("nostr: oversized request envelope")
		return false
	}
	now := t.now()
	createdAt := time.Unix(int64(evt.CreatedAt), 0)
	if evt.Kind != KindRequest ||
		createdAt.Before(now.Add(-requestFreshness)) ||
		createdAt.After(now.Add(requestFutureSkew)) ||
		!hasTagValue(evt.Tags, "p", t.cfg.PublicKey) {
		log.Println("nostr: invalid request envelope", evt.ID)
		return false
	}
	if nip13.CommittedDifficulty(evt) < t.cfg.Offer.MinRequestPoW {
		log.Println("nostr: request proof of work not committed to target", evt.ID)
		return false
	}
	if err := nip13.Check(evt.ID, t.cfg.Offer.MinRequestPoW); err != nil {
		log.Println("nostr: request below required proof of work", evt.ID)
		return false
	}
	if ok, err := evt.CheckSignature(); err != nil || !ok {
		log.Println("nostr: bad request signature", evt.ID)
		return false
	}
	if !t.markRequestSeen(evt.ID, now) {
		log.Println("nostr: duplicate request event", evt.ID)
		return false
	}
	return true
}

func requestEnvelopeWithinBounds(evt *gonostr.Event) bool {
	if evt == nil || len(evt.ID) != 64 || len(evt.PubKey) != 64 || len(evt.Sig) != 128 ||
		len(evt.Content) > maxRequestContent || len(evt.Tags) > maxRequestTags {
		return false
	}
	totalTagBytes := 0
	nonceTags := 0
	for _, tag := range evt.Tags {
		if len(tag) == 0 || len(tag) > maxRequestTagItems {
			return false
		}
		if tag[0] == "nonce" {
			nonceTags++
			if len(tag) != 3 {
				return false
			}
		}
		for _, item := range tag {
			totalTagBytes += len(item)
			if totalTagBytes > maxRequestTagBytes {
				return false
			}
		}
	}
	return nonceTags == 1
}

func (t *Transport) handleRequest(ctx context.Context, relayEvent gonostr.RelayEvent) {
	evt := relayEvent.Event

	convKey, err := nip44.GenerateConversationKey(evt.PubKey, t.cfg.SecretKey)
	if err != nil {
		log.Println("nostr: conversation key error", err)
		return
	}
	plaintext, err := nip44.Decrypt(evt.Content, convKey)
	if err != nil {
		log.Println("nostr: decrypt error", err)
		return
	}
	var req Request
	if err := json.Unmarshal([]byte(plaintext), &req); err != nil {
		t.reply(ctx, relayEvent, convKey, errorResponse("bad request"))
		return
	}

	resp := t.handler.Wrap(req)
	t.reply(ctx, relayEvent, convKey, resp)
}

func hasTagValue(tags gonostr.Tags, name, value string) bool {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == name && tag[1] == value {
			return true
		}
	}
	return false
}

func (t *Transport) markRequestSeen(id string, now time.Time) bool {
	t.seenMu.Lock()
	defer t.seenMu.Unlock()

	cutoff := now.Add(-requestFreshness)
	for seenID, seenAt := range t.seenRequests {
		if seenAt.Before(cutoff) {
			delete(t.seenRequests, seenID)
		}
	}
	if _, ok := t.seenRequests[id]; ok {
		return false
	}
	if len(t.seenRequests) >= maxSeenRequests {
		return false
	}
	t.seenRequests[id] = now
	return true
}

// reply encrypts resp and publishes it as a kind 21822 response addressed to the
// requester.
func (t *Transport) reply(ctx context.Context, relayEvent gonostr.RelayEvent, convKey [32]byte, resp Response) {
	reqEvt := relayEvent.Event
	plaintext, err := MarshalResponse(resp)
	if err != nil {
		log.Println("nostr: marshal response error", err)
		return
	}
	ciphertext, err := nip44.Encrypt(plaintext, convKey)
	if err != nil {
		log.Println("nostr: encrypt response error", err)
		return
	}
	evt := gonostr.Event{
		PubKey:    t.cfg.PublicKey,
		CreatedAt: gonostr.Now(),
		Kind:      KindResponse,
		Tags: gonostr.Tags{
			{"p", reqEvt.PubKey},
			{"e", reqEvt.ID},
		},
		Content: string(ciphertext),
	}
	// A light proof of work keeps responses acceptable to relays enforcing a floor.
	if t.responsePoWTarget > 0 {
		nonceTag, err := nip13.DoWork(ctx, evt, t.responsePoWTarget)
		if err != nil {
			log.Println("nostr: response proof of work error", err)
			return
		}
		evt.Tags = append(evt.Tags, nonceTag)
	}
	if err := evt.Sign(t.cfg.SecretKey); err != nil {
		log.Println("nostr: sign response error", err)
		return
	}
	targetRelays := t.cfg.Relays
	if relayEvent.Relay != nil && relayEvent.Relay.URL != "" {
		for _, configured := range t.cfg.Relays {
			if relayEvent.Relay.URL == configured {
				targetRelays = []string{configured}
				break
			}
		}
	}
	if t.publishResponse(ctx, targetRelays, evt) {
		return
	}
	if len(targetRelays) == 1 {
		fallback := make([]string, 0, len(t.cfg.Relays)-1)
		for _, configured := range t.cfg.Relays {
			if configured != targetRelays[0] {
				fallback = append(fallback, configured)
			}
		}
		if len(fallback) > 0 {
			t.publishResponse(ctx, fallback, evt)
		}
	}
}

func (t *Transport) publishResponse(ctx context.Context, relays []string, evt gonostr.Event) bool {
	success := false
	for result := range t.pool.PublishMany(ctx, relays, evt) {
		if result.Error != nil {
			log.Printf("nostr: response publish to %s failed: %v", result.RelayURL, result.Error)
			continue
		}
		success = true
	}
	return success
}
