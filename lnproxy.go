package lnproxy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/lnproxy/lnc"
)

var ClientFacing = errors.New("")

type RelayParameters struct {
	MinAmountMsat      uint64
	MinFeeBudgetMsat   uint64
	RoutingFeeBaseMsat uint64
	RoutingFeePPM      uint64
	ExpiryBuffer       uint64
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

type ProxyParameters struct {
	Invoice         string      `json:"invoice"`
	RoutingMsat     MaybeUInt64 `json:"routing_msat"`
	Description     MaybeString `json:"description"`
	DescriptionHash MaybeString `json:"description_hash"`
}

type MaybeUInt64 struct {
	Exists bool
	UInt64 uint64
}

func (mu *MaybeUInt64) Set(u uint64) {
	mu.Exists = true
	mu.UInt64 = u
}

func (mu *MaybeUInt64) UnmarshalJSON(data []byte) error {
	var us *string
	if err := json.Unmarshal(data, &us); err != nil {
		return err
	}
	if us != nil {
		u, err := strconv.ParseUint(*us, 10, 64)
		if err != nil {
			return err
		}
		mu.Exists = true
		mu.UInt64 = u
	} else {
		mu.Exists = false
	}
	return nil
}

type MaybeString struct {
	Exists bool
	String string
}

func (ms *MaybeString) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s != nil {
		ms.Exists = true
		ms.String = *s
	} else {
		ms.Exists = false
	}
	return nil
}

func Wrap(ln lnc.LN, r RelayParameters, x ProxyParameters, p lnc.DecodedInvoice) (*lnc.InvoiceParameters, uint64, error) {
	for flag, _ := range p.Features {
		switch flag {
		case "8", "9", "14", "15", "16", "17", "25", "48", "49", "149", "151":
			// 25 is route blinding
			// 48/49 is payment metadata
			// 148/149 is trampoline routing
			// 150/151 is electrum's trampoline
		default:
			log.Printf("unhandled feature flag: %s\n", x.Invoice)
			return nil, 0, errors.Join(ClientFacing, fmt.Errorf("unknown feature flag: %s", flag))
		}
	}

	if p.NumMsat == 0 {
		return nil, 0, errors.Join(ClientFacing, errors.New("zero amount invoices cannot be relayed trustlessly"))
	}
	if p.NumMsat < r.MinAmountMsat {
		return nil, 0, errors.Join(ClientFacing, errors.New("invoice amount too low"))
	}

	min_fee_budget_msat, min_cltv_delta, err := ln.EstimateRoutingFee(p, 0)
	if err != nil {
		log.Println("could not find route:", x.Invoice, err)
		return nil, 0, errors.Join(ClientFacing, errors.New("could not find route"))
	}

	q := lnc.InvoiceParameters{}
	hash, err := hex.DecodeString(p.PaymentHash)
	if err != nil {
		return nil, 0, err
	}
	q.Hash = hash

	if x.Description.Exists && x.DescriptionHash.Exists {
		return nil, 0, errors.Join(ClientFacing, errors.New("description and description hash cannot both be set"))
	} else if x.Description.Exists {
		q.Memo = x.Description.String
	} else if x.DescriptionHash.Exists {
		description_hash, err := hex.DecodeString(x.DescriptionHash.String)
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

	if p.Timestamp+p.Expiry < uint64(time.Now().Unix())+r.ExpiryBuffer {
		return nil, 0, errors.Join(ClientFacing, errors.New("payment request expiration is too close."))
	}
	q.Expiry = p.Timestamp + p.Expiry - uint64(time.Now().Unix()) - r.ExpiryBuffer

	q.CltvExpiry = min_cltv_delta + r.CltvDeltaAlpha + (min_cltv_delta*r.CltvDeltaBeta)/1_000_000
	if q.CltvExpiry >= r.MaxCltvDelta {
		return nil, 0, errors.Join(ClientFacing, errors.New("cltv_expiry is too long"))
	} else if q.CltvExpiry < r.MinCltvDelta {
		q.CltvExpiry = r.MinCltvDelta
	}

	routing_fee_msat := r.RoutingFeeBaseMsat + (p.NumMsat*r.RoutingFeePPM)/1_000_000
	if x.RoutingMsat.Exists {
		if x.RoutingMsat.UInt64 < (r.MinFeeBudgetMsat + routing_fee_msat) {
			return nil, 0, errors.Join(ClientFacing, errors.New("custom fee budget too low"))
		}
		q.ValueMsat = p.NumMsat + x.RoutingMsat.UInt64
		return &q, x.RoutingMsat.UInt64 - routing_fee_msat, nil
	}
	fee_budget_msat := min_fee_budget_msat + r.RoutingBudgetAlpha + (min_fee_budget_msat*r.RoutingBudgetBeta)/1_000_000
	q.ValueMsat = p.NumMsat + fee_budget_msat + routing_fee_msat
	return &q, fee_budget_msat, nil
}

func Relay(ln lnc.LN, r RelayParameters, x ProxyParameters) (string, error) {
	p, err := ln.DecodeInvoice(x.Invoice)
	if err != nil {
		return "", err
	}

	q, fee_budget_msat, err := Wrap(ln, r, x, *p)
	if err != nil {
		return "", err
	}

	proxy_invoice, err := ln.AddInvoice(*q)
	if errors.Is(err, lnc.PaymentHashExists) {
		return "", errors.Join(ClientFacing, lnc.PaymentHashExists)
	} else if err != nil {
		return "", err
	}

	go func() {
		_, err := ln.WatchInvoice(q.Hash)
		if err != nil {
			log.Println("error while watching wrapped invoice:", x.Invoice, err)
			err := ln.CancelInvoice(q.Hash)
			if err != nil {
				log.Println("error while canceling invoice:", x.Invoice, err)
			}
			return
		}
		preimage, err := ln.PayInvoice(lnc.PaymentParameters{
			Invoice:        x.Invoice,
			TimeoutSeconds: r.PaymentTimeout,
			FeeLimitMsat:   fee_budget_msat,
			CltvLimit:      q.CltvExpiry - r.CltvDeltaAlpha,
		})
		if err != nil {
			log.Println("error paying original invoice:", x.Invoice, err)
			err := ln.CancelInvoice(q.Hash)
			if err != nil {
				log.Println("error while canceling invoice:", x.Invoice, err)
			}
			return
		}
		err = ln.SettleInvoice(preimage)
		if err != nil {
			log.Panicln("error while settling original invoice:", x.Invoice, err)
		}
		log.Println("relay circuit successful")
	}()

	return proxy_invoice, nil
}
