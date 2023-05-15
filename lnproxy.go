package lnproxy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"
	"strconv"
)

type RelayParameters struct {
	MinAmountMsat            uint64
	DefaultFeeBudgetBaseMsat uint64
	DefaultFeeBudgetPPM      uint64
	MinFeeBudgetMsat         uint64
	RoutingFeeBaseMsat       uint64
	RoutingFeePPM            uint64
	ExpiryBuffer             uint64
	CltvDeltaAlpha           uint64
	CltvDeltaBeta            uint64
	// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
	MaxCltvDelta uint64
	// Should be set so that CltvDeltaAlpha blocks are very unlikely to be added before timeout
	PaymentTimeout        uint64
	PaymentTimePreference float64
}

type ProxyParameters struct {
	Invoice         string      `json:"invoice"`
	RoutingMsat     MaybeUInt64 `json:"routing_msat"`
	AmountMsat      MaybeUInt64 `json:"amount_msat"`
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

var InternalError = errors.New("Interenal error")

func Wrap(r RelayParameters, x ProxyParameters, p DecodedInvoice) (*InvoiceParameters, uint64, error) {
	for flag, feature := range p.Features {
		switch flag {
		case "8", "9", "14", "15", "16", "17", "48", "49":
		default:
			log.Printf("unhandled feature flag: %s\n\t%v\n", flag, feature)
			if feature.IsRequired {
				return nil, 0, fmt.Errorf("invalid required feature: %s (%s)", feature.Name, flag)
			}
		}
	}

	q := InvoiceParameters{}

	hash, err := hex.DecodeString(p.PaymentHash)
	if err != nil {
		return nil, 0, errors.Join(InternalError, err)
	}
	q.Hash = hash

	if x.Description.Exists && x.DescriptionHash.Exists {
		return nil, 0, fmt.Errorf("description and description hash cannot both be set")
	} else if x.Description.Exists {
		q.Memo = x.Description.String
	} else if x.DescriptionHash.Exists {
		description_hash, err := hex.DecodeString(x.DescriptionHash.String)
		if err != nil {
			return nil, 0, errors.Join(InternalError, err)
		}
		q.DescriptionHash = description_hash
	} else if p.DescriptionHash != "" {
		description_hash, err := hex.DecodeString(p.DescriptionHash)
		if err != nil {
			return nil, 0, errors.Join(InternalError, err)
		}
		q.DescriptionHash = description_hash
	} else {
		q.Memo = p.Description
	}

	q.Expiry = p.Timestamp + p.Expiry - uint64(time.Now().Unix()) - r.ExpiryBuffer
	if q.Expiry < 0 {
		return nil, 0, fmt.Errorf("payment request expiration is too close.")
	}
	q.CltvExpiry = p.CltvExpiry*r.CltvDeltaBeta + r.CltvDeltaAlpha
	if q.CltvExpiry >= r.MaxCltvDelta {
		return nil, 0, fmt.Errorf("cltv_expiry is too long")
	}

	var fee_budget_msat uint64
	if x.RoutingMsat.Exists {
		fee_budget_msat = x.RoutingMsat.UInt64
	} else if x.AmountMsat.Exists && p.NumMsat > 0 {
		if x.AmountMsat.UInt64 < p.NumMsat {
			return nil, 0, fmt.Errorf("proxy amount must be more than original amount")
		}
		fee_budget_msat = x.AmountMsat.UInt64 - p.NumMsat
	} else if p.NumMsat > 0 {
		fee_budget_msat = r.DefaultFeeBudgetBaseMsat + (r.DefaultFeeBudgetPPM*p.NumMsat)/1_000_000
	} else if x.AmountMsat.Exists {
		fee_budget_msat = x.AmountMsat.UInt64
	} else {
		return &q, 0, nil
	}

	if fee_budget_msat < (r.MinFeeBudgetMsat + r.RoutingFeeBaseMsat + (r.RoutingFeePPM*p.NumMsat)/1_000_000) {
		return nil, 0, fmt.Errorf("fee budget too low")
	}
	if p.NumMsat == 0 {
		return &q, fee_budget_msat, nil
	}
	if p.NumMsat < r.MinAmountMsat {
		return nil, 0, fmt.Errorf("invoice amount too low")
	}
	q.ValueMsat = p.NumMsat + fee_budget_msat
	return &q, fee_budget_msat, nil
}

func Relay(ln LN, r RelayParameters, x ProxyParameters) (string, error) {
	p, err := ln.DecodeInvoice(x.Invoice)
	if err != nil {
		return "", err
	}
	q, fee_budget_msat, err := Wrap(r, x, *p)
	if err != nil {
		return "", err
	}
	proxy_invoice, err := ln.AddInvoice(*q)
	if err != nil {
		return "", err
	}
	go func() {
		amt_paid_msat, err := ln.WatchInvoice(q.Hash)
		if err != nil {
			log.Println("Error while watching wrapped invoice:", x.Invoice, err)
			err := ln.CancelInvoice(q.Hash)
			if err != nil {
				log.Println("error while canceling invoice:", x.Invoice, err)
			}
			return
		}
		amount_msat := p.NumMsat
		routing_fee_msat := r.RoutingFeeBaseMsat + (amt_paid_msat*r.RoutingFeePPM)/1_000_000
		if fee_budget_msat == 0 {
			if amt_paid_msat < routing_fee_msat+r.MinFeeBudgetMsat {
				log.Println("Payment to zero amount invoice too low", x.Invoice)
				err := ln.CancelInvoice(q.Hash)
				if err != nil {
					log.Println("error while canceling invoice:", x.Invoice, err)
				}
				return
			}
			fee_budget_msat = amt_paid_msat - routing_fee_msat
		} else if amount_msat == 0 {
			if amt_paid_msat <= fee_budget_msat || amt_paid_msat < (r.MinAmountMsat+fee_budget_msat) {
				log.Println("Amount paid too low", x.Invoice)
				err := ln.CancelInvoice(q.Hash)
				if err != nil {
					log.Println("error while canceling invoice:", x.Invoice, err)
				}
				return
			}
			if q.ValueMsat > 0 {
				amount_msat = q.ValueMsat - fee_budget_msat
			} else {
				amount_msat = amt_paid_msat - fee_budget_msat
			}
		}
		payment := PaymentParameters{
			Invoice:           x.Invoice,
			TimeoutSeconds:    r.PaymentTimeout,
			AmtMsat:           amount_msat,
			FeeLimitMsat:      fee_budget_msat - routing_fee_msat,
			NoInflightUpdates: true,
			CltvLimit:         q.CltvExpiry - r.CltvDeltaAlpha,
			Amp:               false,
			TimePref:          r.PaymentTimePreference,
		}
		preimage, err := ln.PayInvoice(payment)
		if err != nil {
			log.Println("Error paying original invoice:", x.Invoice, err)
			err := ln.CancelInvoice(q.Hash)
			if err != nil {
				log.Println("error while canceling invoice:", x.Invoice, err)
			}
			return
		}
		err = ln.SettleInvoice(preimage)
		if err != nil {
			log.Panicln("Error while settling original invoice:", x.Invoice, err)
		}
		log.Println("Relay circuit successful")
	}()
	return proxy_invoice, nil
}
