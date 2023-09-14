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

type Relay struct {
	RelayParameters
	lnc.LN
	sync.WaitGroup
}

type RelayParameters struct {
	MinAmountMsat      uint64
	MaxAmountMsat      uint64
	MinFeeBudgetMsat   uint64
	RoutingFeeBaseMsat uint64
	RoutingFeePPM      uint64
	ExpiryBuffer       uint64
	MaxExpiry          uint64
	CltvDeltaAlpha     uint64
	CltvDeltaBeta      uint64
	RoutingBudgetAlpha uint64
	RoutingBudgetBeta  uint64
	// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
	MaxCltvDelta uint64
	MinCltvDelta uint64
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
			MaxExpiry:          604800, // 60*60*24*7 one week
			MinFeeBudgetMsat:   1000,
			RoutingBudgetAlpha: 1000,
			RoutingBudgetBeta:  1_500_000,
			RoutingFeeBaseMsat: 1000,
			RoutingFeePPM:      1000,
			CltvDeltaAlpha:     144,
			CltvDeltaBeta:      1_500_000,
			// Should be set to at most the node's `--max-cltv-expiry` setting (default: 2016)
			MaxCltvDelta: 1800,
			MinCltvDelta: 120,
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
		log.Println("route estimation error:", err)
		return nil, 0, errors.Join(ClientFacing, errors.New("could not find route"))
	}
	for flag, _ := range p.Features {
		switch flag {
		case "8", "9", "14", "15", "16", "17", "25", "48", "49", "149", "151":
			// 25 is route blinding
			// 48/49 is payment metadata
			// 148/149 is trampoline routing
			// 150/151 is electrum's trampoline
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

	if p.Timestamp+p.Expiry < uint64(time.Now().Unix())+relay.ExpiryBuffer {
		return nil, 0, errors.Join(ClientFacing, errors.New("payment request expiration is too close."))
	}
	expiry := p.Expiry
	if expiry > relay.MaxExpiry {
		expiry = relay.MaxExpiry
	}
	q.Expiry = p.Timestamp + expiry - uint64(time.Now().Unix()) - relay.ExpiryBuffer

	q.CltvExpiry = min_cltv_delta + relay.CltvDeltaAlpha + (min_cltv_delta*relay.CltvDeltaBeta)/1_000_000
	if q.CltvExpiry >= relay.MaxCltvDelta {
		return nil, 0, errors.Join(ClientFacing, errors.New("cltv_expiry is too long"))
	} else if q.CltvExpiry < relay.MinCltvDelta {
		q.CltvExpiry = relay.MinCltvDelta
	}

	routing_fee_msat := relay.RoutingFeeBaseMsat + (p.NumMsat*relay.RoutingFeePPM)/1_000_000
	if x.RoutingMsat != nil {
		if *x.RoutingMsat < (relay.MinFeeBudgetMsat + routing_fee_msat) {
			return nil, 0, errors.Join(ClientFacing, errors.New("custom fee budget too low"))
		}
		q.ValueMsat = p.NumMsat + *x.RoutingMsat
		return &q, *x.RoutingMsat - routing_fee_msat, nil
	}
	fee_budget_msat = min_fee_budget_msat + relay.RoutingBudgetAlpha + (min_fee_budget_msat*relay.RoutingBudgetBeta)/1_000_000
	q.ValueMsat = p.NumMsat + fee_budget_msat + routing_fee_msat
	return &q, fee_budget_msat, nil
}

// Takes an lnproxy request, validates that it can be proxied securely,
// opens a circuit that will be completed when invoice is successfully relayed,
// and returns a wrapped invoice.
func (relay *Relay) OpenCircuit(x ProxyParameters) (string, error) {
	proxy_invoice_params, fee_budget_msat, err := relay.wrap(x)
	if err != nil {
		return "", err
	}

	proxy_invoice, err := relay.LN.AddInvoice(*proxy_invoice_params)
	if errors.Is(err, lnc.PaymentHashExists) {
		return "", errors.Join(ClientFacing, lnc.PaymentHashExists)
	} else if err != nil {
		return "", err
	}

	relay.WaitGroup.Add(1)
	go relay.circuitSwitch(proxy_invoice_params.Hash, x.Invoice, fee_budget_msat, proxy_invoice_params.CltvExpiry-relay.CltvDeltaAlpha)

	return proxy_invoice, nil
}

func (relay *Relay) circuitSwitch(hash []byte, invoice string, fee_budget_msat, cltv_limit uint64) {
	defer relay.WaitGroup.Done()
	log.Println("opened circuit for:", invoice, hex.EncodeToString(hash))
	_, err := relay.LN.WatchInvoice(hash)
	if err != nil {
		log.Println("error while watching wrapped invoice:", hex.EncodeToString(hash), err)
		err = relay.LN.CancelInvoice(hash)
		if err != nil {
			log.Println("error while canceling invoice:", hash, err)
		}
		return
	}
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
