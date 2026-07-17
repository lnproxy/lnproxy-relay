package relay

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lnproxy/lnc"
)

var ClientFacing = errors.New("")
var noCircuitOpened = errors.New("")

const defaultMaxActiveCircuits uint64 = 128

type Relay struct {
	RelayParameters
	lnc.LN
	sync.WaitGroup
	activeMu       sync.Mutex
	activeCircuits uint64
}

type RelayParameters struct {
	MinAmountMsat      uint64
	MaxAmountMsat      uint64
	MinFeeBudgetMsat   uint64
	RoutingFeeBaseMsat uint64
	RoutingFeePPM      uint64
	ExpiryBuffer       uint64
	MaxExpiry          uint64
	MaxActiveCircuits  uint64
	CltvDeltaAlpha     uint64
	CltvDeltaBeta      uint64
	RoutingBudgetAlpha uint64
	RoutingBudgetBeta  uint64
	// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
	MaxCltvExpiry uint64
	MinCltvExpiry uint64
	// Should be set so that CltvDeltaAlpha blocks are very unlikely to be added before timeout
	PaymentTimeout        uint64
	PaymentTimePreference float64
}

// Returns a Relay with with sane defaults
func NewRelay(ln lnc.LN) *Relay {
	return &Relay{
		RelayParameters: RelayParameters{
			MinAmountMsat:      10_000,
			MaxAmountMsat:      1_000_000_000,
			ExpiryBuffer:       300,
			MaxExpiry:          3600,
			MaxActiveCircuits:  defaultMaxActiveCircuits,
			MinFeeBudgetMsat:   1000,
			RoutingBudgetAlpha: 1000,
			RoutingBudgetBeta:  1_500_000,
			RoutingFeeBaseMsat: 1000,
			RoutingFeePPM:      1000,
			CltvDeltaAlpha:     42,
			CltvDeltaBeta:      42,
			// Should be set to at most the node's `--max-cltv-expiry` setting (default: 2016)
			MaxCltvExpiry: 1800,
			MinCltvExpiry: 420,
			// Should be set so that CltvDeltaAlpha blocks are very unlikely to be added before timeout
			PaymentTimeout:        60,
			PaymentTimePreference: 0.9,
		},
		LN: ln,
	}
}

// Parameters for lnproxy requests
type ProxyParameters struct {
	Invoice         string  `json:"invoice"`
	RoutingMsat     *uint64 `json:"routing_msat,string"`
	Description     *string `json:"description"`
	DescriptionHash *string `json:"description_hash"`
}

func (x ProxyParameters) String() string {
	result := fmt.Sprintf("ProxyParameters {Invoice:%s", x.Invoice)
	if x.RoutingMsat != nil {
		result += fmt.Sprintf(" RoutingMsat:%d", *(x.RoutingMsat))
	}
	if x.Description != nil {
		result += fmt.Sprintf(" Description:\"%s\"", *(x.Description))
	} else if x.DescriptionHash != nil {
		result += fmt.Sprintf(" DescriptionHash:%s", *(x.DescriptionHash))
	}
	return result + "}"
}

func (relay *Relay) wrap(x ProxyParameters) (proxy_invoice_params *lnc.InvoiceParameters, fee_budget_msat uint64, err error) {
	p, err := relay.LN.DecodeInvoice(x.Invoice)
	if err != nil {
		return nil, 0, err
	}

	if p.NumMsat == 0 {
		return nil, 0, errors.Join(ClientFacing, errors.New("zero amount invoices cannot be relayed trustlessly"))
	}
	if p.NumMsat < relay.MinAmountMsat {
		return nil, 0, errors.Join(ClientFacing, errors.New("invoice amount too low"))
	}
	if p.NumMsat > relay.MaxAmountMsat {
		return nil, 0, errors.Join(ClientFacing, errors.New("invoice amount too high"))
	}

	min_fee_budget_msat, min_cltv_delta, err := relay.LN.EstimateRoutingFee(*p, 0)
	if err != nil {
		// log.Println("route estimation error:", err)
		// return nil, 0, errors.Join(ClientFacing, errors.New("could not find route"))
		min_fee_budget_msat = 1000
		min_cltv_delta = 144
	}
	for flag, _ := range p.Features {
		switch flag {
		case "8", "9", "14", "15", "16", "17", "25", "48", "49", "149", "151", "262", "263":
			// 25 is route blinding
			// 48/49 is payment metadata
			// 148/149 is trampoline routing
			// 150/151 is electrum's trampoline
			// 262/263 is bolt11 blinded paths
		default:
			return nil, 0, errors.Join(ClientFacing, fmt.Errorf("unknown feature flag: %s", flag))
		}
	}

	q := lnc.InvoiceParameters{}
	hash, err := hex.DecodeString(p.PaymentHash)
	if err != nil {
		return nil, 0, err
	}
	q.Hash = hash

	if x.Description != nil && x.DescriptionHash != nil {
		return nil, 0, errors.Join(ClientFacing, errors.New("description and description hash cannot both be set"))
	} else if x.Description != nil {
		q.Memo = *x.Description
	} else if x.DescriptionHash != nil {
		description_hash, err := hex.DecodeString(*x.DescriptionHash)
		if err != nil {
			return nil, 0, err
		}
		q.DescriptionHash = description_hash
	} else if p.DescriptionHash != "" {
		description_hash, err := hex.DecodeString(p.DescriptionHash)
		if err != nil {
			return nil, 0, err
		}
		q.DescriptionHash = description_hash
	} else {
		q.Memo = p.Description
	}

	now := uint64(time.Now().Unix())
	expiresAt, err := checkedAdd(p.Timestamp, p.Expiry)
	if err != nil {
		return nil, 0, errors.Join(ClientFacing, errors.New("invalid payment request expiration"))
	}
	minimumExpiry, err := checkedAdd(now, relay.ExpiryBuffer)
	if err != nil || expiresAt <= minimumExpiry {
		return nil, 0, errors.Join(ClientFacing, errors.New("payment request expiration is too close."))
	}
	remainingExpiry := expiresAt - minimumExpiry
	if remainingExpiry > relay.MaxExpiry {
		remainingExpiry = relay.MaxExpiry
	}
	q.Expiry = remainingExpiry

	q.CltvExpiry, err = checkedAdd(min_cltv_delta, relay.CltvDeltaBeta)
	if err == nil {
		q.CltvExpiry, err = checkedAdd(q.CltvExpiry, relay.CltvDeltaAlpha)
	}
	if err != nil {
		return nil, 0, errors.Join(ClientFacing, errors.New("cltv_expiry is too long"))
	}
	if q.CltvExpiry >= relay.MaxCltvExpiry {
		return nil, 0, errors.Join(ClientFacing, errors.New("cltv_expiry is too long"))
	} else if q.CltvExpiry < relay.MinCltvExpiry {
		q.CltvExpiry = relay.MinCltvExpiry
	}

	routing_fee_msat, err := relay.RelayParameters.effectiveFeeMsat(p.NumMsat)
	if err != nil {
		return nil, 0, errors.Join(ClientFacing, errors.New("fee calculation overflow"))
	}
	if x.RoutingMsat != nil {
		minimumRoutingMsat, err := checkedAdd(relay.MinFeeBudgetMsat, routing_fee_msat)
		if err != nil || *x.RoutingMsat < minimumRoutingMsat {
			return nil, 0, errors.Join(ClientFacing, errors.New("custom fee budget too low"))
		}
		q.ValueMsat, err = checkedAdd(p.NumMsat, *x.RoutingMsat)
		if err != nil {
			return nil, 0, errors.Join(ClientFacing, errors.New("custom fee budget too high"))
		}
		return &q, *x.RoutingMsat - routing_fee_msat, nil
	}
	proportionalBudget, err := checkedMulDiv(min_fee_budget_msat, relay.RoutingBudgetBeta, 1_000_000)
	if err != nil {
		return nil, 0, errors.Join(ClientFacing, errors.New("routing budget calculation overflow"))
	}
	fee_budget_msat, err = checkedAdd(min_fee_budget_msat, relay.RoutingBudgetAlpha)
	if err == nil {
		fee_budget_msat, err = checkedAdd(fee_budget_msat, proportionalBudget)
	}
	if err != nil {
		return nil, 0, errors.Join(ClientFacing, errors.New("routing budget calculation overflow"))
	}
	q.ValueMsat, err = checkedAdd(p.NumMsat, fee_budget_msat)
	if err == nil {
		q.ValueMsat, err = checkedAdd(q.ValueMsat, routing_fee_msat)
	}
	if err != nil {
		return nil, 0, errors.Join(ClientFacing, errors.New("proxy amount overflow"))
	}
	return &q, fee_budget_msat, nil
}

// Takes an lnproxy request, validates that it can be proxied securely,
// opens a circuit that will be completed when invoice is successfully relayed,
// and returns a wrapped invoice.
func (relay *Relay) OpenCircuit(x ProxyParameters) (string, error) {
	if !relay.acquireCircuit() {
		return "", errors.Join(noCircuitOpened, ClientFacing, errors.New("relay is at active circuit capacity"))
	}
	proxy_invoice_params, fee_budget_msat, err := relay.wrap(x)
	if err != nil {
		relay.releaseCircuit()
		return "", errors.Join(noCircuitOpened, err)
	}

	proxy_invoice, err := relay.LN.AddInvoice(*proxy_invoice_params)
	if errors.Is(err, lnc.PaymentHashExists) {
		relay.releaseCircuit()
		return "", errors.Join(noCircuitOpened, ClientFacing, lnc.PaymentHashExists)
	} else if err != nil {
		relay.releaseCircuit()
		return "", err
	}

	relay.WaitGroup.Add(1)
	go relay.circuitSwitch(proxy_invoice_params.Hash, x.Invoice, fee_budget_msat)

	return proxy_invoice, nil
}

func (relay *Relay) circuitSwitch(hash []byte, invoice string, fee_budget_msat uint64) {
	defer relay.WaitGroup.Done()
	defer relay.releaseCircuit()
	log.Println("opened circuit for:", invoice, hex.EncodeToString(hash))
	invoice_state, err := relay.LN.WatchInvoice(hash)
	if err != nil || invoice_state == nil || invoice_state.State != lnc.Accepted {
		var state any = "unknown"
		if invoice_state != nil {
			state = invoice_state.State
		}
		log.Println("error while watching wrapped invoice:", hex.EncodeToString(hash), state, err)
		if invoice_state == nil || invoice_state.State != lnc.Canceled {
			err = relay.LN.CancelInvoice(hash)
			if err != nil {
				log.Println("error while canceling invoice:", hash, err)
			}
		}
		return
	}
	// The outgoing payment to the original invoice must time out before the
	// accepted proxy-invoice HTLC does, by at least CltvDeltaAlpha blocks, so
	// that the relay always learns the preimage (and can settle the proxy
	// invoice) before its incoming HTLC can be pulled back. The proxy invoice's
	// min_final_cltv_expiry (>= MinCltvExpiry) guarantees this margin, but guard
	// against a misconfiguration or an unexpectedly short accepted HTLC rather
	// than letting the uint64 subtraction underflow into an unbounded CltvLimit,
	// which would remove the safety margin and risk relay funds.
	if invoice_state.CltvExpiryDelta <= relay.CltvDeltaAlpha {
		log.Println("accepted HTLC cltv delta too short to pay out safely, canceling:",
			hex.EncodeToString(hash), invoice_state.CltvExpiryDelta, relay.CltvDeltaAlpha)
		err = relay.LN.CancelInvoice(hash)
		if err != nil {
			log.Println("error while canceling invoice:", hash, err)
		}
		return
	}
	cltv_limit := invoice_state.CltvExpiryDelta - relay.CltvDeltaAlpha
	preimage, err := relay.LN.PayInvoice(lnc.PaymentParameters{
		Invoice:        invoice,
		TimeoutSeconds: relay.PaymentTimeout,
		FeeLimitMsat:   fee_budget_msat,
		CltvLimit:      cltv_limit,
	})
	if errors.Is(err, lnc.PaymentFailed) {
		log.Println("payment failed", hex.EncodeToString(hash), err)
		err = relay.LN.CancelInvoice(hash)
		if err != nil {
			log.Println("error while canceling invoice:", hash, err)
		}
		return
	} else if err != nil {
		log.Panicln("payment in unknown state:", hex.EncodeToString(hash), err)
	}
	log.Println("preimage:", hex.EncodeToString(preimage), hex.EncodeToString(hash))
	err = relay.LN.SettleInvoice(preimage)
	if err != nil {
		log.Panicln("error while settling original invoice:", hex.EncodeToString(hash), err)
	}
	log.Println("circuit settled")
	return
}

func (relay *Relay) acquireCircuit() bool {
	relay.activeMu.Lock()
	defer relay.activeMu.Unlock()
	limit := relay.MaxActiveCircuits
	if limit == 0 {
		// Preserve compatibility for callers that construct RelayParameters
		// directly and therefore leave newly added fields at their zero value.
		limit = defaultMaxActiveCircuits
	}
	if relay.activeCircuits >= limit {
		return false
	}
	relay.activeCircuits++
	return true
}

func (relay *Relay) releaseCircuit() {
	relay.activeMu.Lock()
	defer relay.activeMu.Unlock()
	if relay.activeCircuits > 0 {
		relay.activeCircuits--
	}
}

// CircuitMayBeOpen reports whether an OpenCircuit error may have occurred after
// the hold-invoice creation request reached LND. Such errors need durable
// idempotency retention because retrying them can encounter an existing invoice.
func CircuitMayBeOpen(err error) bool {
	return err != nil && !errors.Is(err, noCircuitOpened)
}
