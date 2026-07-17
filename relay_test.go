package relay

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/lnproxy/lnc"
)

// fakeLN is a minimal lnc.LN for exercising wrap() feature-flag handling.
type fakeLN struct {
	decoded      *lnc.DecodedInvoice
	addedInvoice lnc.InvoiceParameters
}

func (f *fakeLN) DecodeInvoice(string) (*lnc.DecodedInvoice, error) { return f.decoded, nil }
func (f *fakeLN) AddInvoice(invoice lnc.InvoiceParameters) (string, error) {
	f.addedInvoice = invoice
	return "lnbc-proxy", nil
}
func (f *fakeLN) WatchInvoice([]byte) (*lnc.InvoiceState, error) {
	return &lnc.InvoiceState{State: lnc.Canceled}, nil
}
func (f *fakeLN) CancelInvoice([]byte) error { return nil }
func (f *fakeLN) PayInvoice(lnc.PaymentParameters) ([]byte, error) {
	return nil, lnc.PaymentFailed
}
func (f *fakeLN) SettleInvoice([]byte) error { return nil }
func (f *fakeLN) EstimateRoutingFee(lnc.DecodedInvoice, uint64) (uint64, uint64, error) {
	return 1000, 144, nil
}

func decodedWithFeatures(features ...string) *lnc.DecodedInvoice {
	hash := "0001020304050607080910111213141516171819202122232425262728293031"
	d := &lnc.DecodedInvoice{
		PaymentHash: hash,
		Timestamp:   uint64(time.Now().Unix()),
		Expiry:      3600,
		Description: "test",
		NumMsat:     1_000_000,
		CltvExpiry:  40,
		Destination: "02deadbeef",
	}
	d.Features = map[string]struct {
		Name       string `json:"name"`
		IsRequired bool   `json:"is_required"`
		IsKnown    bool   `json:"is_known"`
	}{}
	for _, f := range features {
		d.Features[f] = struct {
			Name       string `json:"name"`
			IsRequired bool   `json:"is_required"`
			IsKnown    bool   `json:"is_known"`
		}{Name: f}
	}
	return d
}

// TestWrapAcceptsBlindedPathFeatures guards the fix for LND 0.18 invoices, which
// set bolt11 blinded-path feature bit 263. Both 262 and 263 must be accepted.
func TestWrapAcceptsBlindedPathFeatures(t *testing.T) {
	for _, feat := range []string{"262", "263"} {
		t.Run("feature_"+feat, func(t *testing.T) {
			r := NewRelay(&fakeLN{decoded: decodedWithFeatures("8", "14", "17", "25", feat)})
			if _, _, err := r.wrap(ProxyParameters{Invoice: "lnbcrt1..."}); err != nil {
				t.Fatalf("wrap rejected feature %s: %v", feat, err)
			}
		})
	}
}

func TestNewRelayBoundsDefaultProxyExpiry(t *testing.T) {
	r := NewRelay(nil)
	if r.MaxExpiry != uint64(time.Hour.Seconds()) {
		t.Fatalf("MaxExpiry = %d, want %d", r.MaxExpiry, uint64(time.Hour.Seconds()))
	}
}

func TestWrapRejectsUnknownFeature(t *testing.T) {
	r := NewRelay(&fakeLN{decoded: decodedWithFeatures("8", "999")})
	_, _, err := r.wrap(ProxyParameters{Invoice: "lnbcrt1..."})
	if err == nil {
		t.Fatal("expected unknown feature flag to be rejected")
	}
}

func TestWrapRejectsCustomRoutingAmountOverflow(t *testing.T) {
	routingMsat := uint64(math.MaxUint64)
	r := NewRelay(&fakeLN{decoded: decodedWithFeatures("8")})
	_, _, err := r.wrap(ProxyParameters{Invoice: "lnbcrt1...", RoutingMsat: &routingMsat})
	if !errors.Is(err, ClientFacing) {
		t.Fatalf("wrap error = %v, want client-facing overflow rejection", err)
	}
}

func TestWrapRejectsFeeScheduleOverflow(t *testing.T) {
	r := NewRelay(&fakeLN{decoded: decodedWithFeatures("8")})
	r.RoutingFeePPM = math.MaxUint64
	_, _, err := r.wrap(ProxyParameters{Invoice: "lnbcrt1..."})
	if !errors.Is(err, ClientFacing) {
		t.Fatalf("wrap error = %v, want client-facing overflow rejection", err)
	}
}

func TestWrapCapsOldInvoiceByRemainingLifetime(t *testing.T) {
	decoded := decodedWithFeatures("8")
	decoded.Timestamp = uint64(time.Now().Add(-2 * time.Hour).Unix())
	decoded.Expiry = uint64((4 * time.Hour).Seconds())
	r := NewRelay(&fakeLN{decoded: decoded})
	r.MaxExpiry = uint64((7 * 24 * time.Hour).Seconds())
	params, _, err := r.wrap(ProxyParameters{Invoice: "lnbcrt1..."})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	wantMax := uint64((2 * time.Hour).Seconds()) - r.ExpiryBuffer
	if params.Expiry > wantMax {
		t.Fatalf("proxy expiry = %d, want at most remaining lifetime %d", params.Expiry, wantMax)
	}
}

// recordingLN drives a full circuit: WatchInvoice returns an Accepted state with
// a configurable CLTV delta, and it records whether the relay paid out or
// canceled. PayInvoice succeeds with a preimage.
type recordingLN struct {
	decoded      *lnc.DecodedInvoice
	cltvDelta    uint64
	paid         bool
	canceled     bool
	settled      bool
	gotCltvLimit uint64
}

type watchErrorLN struct {
	*fakeLN
	canceled bool
}

func (l *watchErrorLN) WatchInvoice([]byte) (*lnc.InvoiceState, error) {
	return nil, errors.New("watch failed")
}

func (l *watchErrorLN) CancelInvoice([]byte) error {
	l.canceled = true
	return nil
}

func TestCircuitSwitchHandlesNilWatchResult(t *testing.T) {
	ln := &watchErrorLN{fakeLN: &fakeLN{decoded: decodedWithFeatures("8")}}
	r := NewRelay(ln)
	r.WaitGroup.Add(1)
	r.circuitSwitch([]byte("hash"), "lnbc1...", 1000)
	if !ln.canceled {
		t.Fatal("relay did not cancel after invoice watch failed")
	}
}

func (m *recordingLN) DecodeInvoice(string) (*lnc.DecodedInvoice, error) { return m.decoded, nil }
func (m *recordingLN) AddInvoice(lnc.InvoiceParameters) (string, error)  { return "lnbc-proxy", nil }
func (m *recordingLN) WatchInvoice([]byte) (*lnc.InvoiceState, error) {
	return &lnc.InvoiceState{State: lnc.Accepted, CltvExpiryDelta: m.cltvDelta}, nil
}
func (m *recordingLN) CancelInvoice([]byte) error { m.canceled = true; return nil }
func (m *recordingLN) PayInvoice(p lnc.PaymentParameters) ([]byte, error) {
	m.paid = true
	m.gotCltvLimit = p.CltvLimit
	return []byte("preimage-bytes-32-aaaaaaaaaaaaaa"), nil
}
func (m *recordingLN) SettleInvoice([]byte) error { m.settled = true; return nil }
func (m *recordingLN) EstimateRoutingFee(lnc.DecodedInvoice, uint64) (uint64, uint64, error) {
	return 1000, 144, nil
}

// TestCircuitSwitchCancelsOnShortCltv guards against the uint64 underflow in the
// CltvLimit computation: when the accepted HTLC's CLTV delta is not larger than
// CltvDeltaAlpha, the relay must cancel rather than pay out with an unbounded
// CltvLimit (which would risk funds).
func TestCircuitSwitchCancelsOnShortCltv(t *testing.T) {
	r := NewRelay(nil)
	m := &recordingLN{cltvDelta: r.CltvDeltaAlpha} // exactly equal -> unsafe
	r.LN = m
	r.WaitGroup.Add(1)
	r.circuitSwitch([]byte("hash"), "lnbc1...", 1000)
	if m.paid {
		t.Fatal("relay paid out with an unsafe CLTV margin")
	}
	if !m.canceled {
		t.Fatal("relay did not cancel the unsafe invoice")
	}
}

// TestCircuitSwitchPaysWithSafeMargin verifies the happy path: a healthy CLTV
// delta yields CltvLimit = delta - CltvDeltaAlpha and the invoice is settled.
func TestCircuitSwitchPaysWithSafeMargin(t *testing.T) {
	r := NewRelay(nil)
	m := &recordingLN{cltvDelta: 500}
	r.LN = m
	r.WaitGroup.Add(1)
	r.circuitSwitch([]byte("hash"), "lnbc1...", 1000)
	if !m.paid {
		t.Fatal("relay did not pay out with a safe CLTV margin")
	}
	if m.gotCltvLimit != 500-r.CltvDeltaAlpha {
		t.Fatalf("CltvLimit = %d, want %d", m.gotCltvLimit, 500-r.CltvDeltaAlpha)
	}
	if !m.settled {
		t.Fatal("relay did not settle after learning the preimage")
	}
}

type capacityLN struct {
	*fakeLN
	mu      sync.Mutex
	adds    int
	addErr  error
	started chan struct{}
	release chan struct{}
}

func (l *capacityLN) AddInvoice(lnc.InvoiceParameters) (string, error) {
	l.mu.Lock()
	l.adds++
	err := l.addErr
	l.mu.Unlock()
	return "lnbc-proxy", err
}

func (l *capacityLN) WatchInvoice([]byte) (*lnc.InvoiceState, error) {
	close(l.started)
	<-l.release
	return &lnc.InvoiceState{State: lnc.Canceled}, nil
}

func (l *capacityLN) addCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.adds
}

func TestOpenCircuitEnforcesActiveCircuitCapacity(t *testing.T) {
	ln := &capacityLN{
		fakeLN:  &fakeLN{decoded: decodedWithFeatures("8")},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	r := NewRelay(ln)
	r.MaxActiveCircuits = 1
	if _, err := r.OpenCircuit(ProxyParameters{Invoice: "lnbcrt1..."}); err != nil {
		t.Fatalf("first OpenCircuit: %v", err)
	}
	<-ln.started

	if _, err := r.OpenCircuit(ProxyParameters{Invoice: "lnbcrt1..."}); !errors.Is(err, ClientFacing) {
		t.Fatalf("second OpenCircuit error = %v, want client-facing capacity error", err)
	} else if CircuitMayBeOpen(err) {
		t.Fatalf("capacity error unexpectedly marked as possibly open: %v", err)
	}
	if got := ln.addCalls(); got != 1 {
		t.Fatalf("AddInvoice calls = %d, want 1", got)
	}

	close(ln.release)
	r.WaitGroup.Wait()
}

func TestOpenCircuitUsesDefaultCapacityWhenLimitIsOmitted(t *testing.T) {
	r := &Relay{}
	for i := uint64(0); i < defaultMaxActiveCircuits; i++ {
		if !r.acquireCircuit() {
			t.Fatalf("acquireCircuit rejected circuit %d before default capacity", i+1)
		}
	}
	if r.acquireCircuit() {
		t.Fatal("acquireCircuit exceeded default capacity")
	}
}

func TestOpenCircuitReleasesCapacityAfterAddInvoiceError(t *testing.T) {
	addErr := errors.New("add invoice response lost")
	ln := &capacityLN{
		fakeLN: &fakeLN{decoded: decodedWithFeatures("8")},
		addErr: addErr,
	}
	r := NewRelay(ln)
	r.MaxActiveCircuits = 1

	_, err := r.OpenCircuit(ProxyParameters{Invoice: "lnbcrt1..."})
	if !errors.Is(err, addErr) {
		t.Fatalf("OpenCircuit error = %v, want %v", err, addErr)
	}
	if !CircuitMayBeOpen(err) {
		t.Fatalf("uncertain AddInvoice error marked side-effect-free: %v", err)
	}

	ln.mu.Lock()
	ln.addErr = lnc.PaymentHashExists
	ln.mu.Unlock()
	_, err = r.OpenCircuit(ProxyParameters{Invoice: "lnbcrt1..."})
	if !errors.Is(err, lnc.PaymentHashExists) {
		t.Fatalf("second OpenCircuit error = %v, want PaymentHashExists", err)
	}
	if CircuitMayBeOpen(err) {
		t.Fatalf("definite PaymentHashExists error marked as possibly opened: %v", err)
	}
}

func TestCircuitMayBeOpenRejectsPreInvoiceErrors(t *testing.T) {
	r := NewRelay(&fakeLN{decoded: decodedWithFeatures("999")})
	_, err := r.OpenCircuit(ProxyParameters{Invoice: "lnbcrt1..."})
	if err == nil {
		t.Fatal("OpenCircuit unexpectedly accepted unsupported invoice")
	}
	if CircuitMayBeOpen(err) {
		t.Fatalf("validation error marked as possibly opened: %v", err)
	}
}
