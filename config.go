package relay

import (
	"fmt"
	"math"
	"math/bits"
	"os"
	"strconv"
)

// envOr returns the value of the environment variable named key parsed as a
// uint64, or fallback if the variable is unset or empty. It returns an error if
// the variable is set but cannot be parsed.
func envOrUint64(key string, fallback uint64) (uint64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return n, nil
}

// ApplyEnvOverrides overrides the operator-tunable fee and limit fields of p
// from environment variables, leaving any unset variable at its current value.
// It is used by the relay binaries so that operators can set their own fees and
// amount limits without recompiling.
//
// Recognized variables:
//
//	LNPROXY_MIN_MSAT       -> MinAmountMsat
//	LNPROXY_MAX_MSAT       -> MaxAmountMsat
//	LNPROXY_BASE_FEE_MSAT  -> RoutingFeeBaseMsat
//	LNPROXY_FEE_PPM        -> RoutingFeePPM
//	LNPROXY_MAX_EXPIRY     -> MaxExpiry (seconds)
//	LNPROXY_MAX_ACTIVE_CIRCUITS -> MaxActiveCircuits
func (p *RelayParameters) ApplyEnvOverrides() error {
	var err error
	if p.MinAmountMsat, err = envOrUint64("LNPROXY_MIN_MSAT", p.MinAmountMsat); err != nil {
		return err
	}
	if p.MaxAmountMsat, err = envOrUint64("LNPROXY_MAX_MSAT", p.MaxAmountMsat); err != nil {
		return err
	}
	if p.RoutingFeeBaseMsat, err = envOrUint64("LNPROXY_BASE_FEE_MSAT", p.RoutingFeeBaseMsat); err != nil {
		return err
	}
	if p.RoutingFeePPM, err = envOrUint64("LNPROXY_FEE_PPM", p.RoutingFeePPM); err != nil {
		return err
	}
	if p.MaxExpiry, err = envOrUint64("LNPROXY_MAX_EXPIRY", p.MaxExpiry); err != nil {
		return err
	}
	if p.MaxActiveCircuits, err = envOrUint64("LNPROXY_MAX_ACTIVE_CIRCUITS", p.MaxActiveCircuits); err != nil {
		return err
	}
	return nil
}

// Validate checks that the fee and limit parameters are internally consistent.
func (p RelayParameters) Validate() error {
	if p.MinAmountMsat == 0 {
		return fmt.Errorf("min amount must be greater than zero")
	}
	if p.MaxAmountMsat < p.MinAmountMsat {
		return fmt.Errorf("max amount (%d) must be >= min amount (%d)", p.MaxAmountMsat, p.MinAmountMsat)
	}
	if p.MaxExpiry == 0 {
		return fmt.Errorf("max expiry must be greater than zero")
	}
	if _, err := p.effectiveFeeMsat(p.MaxAmountMsat); err != nil {
		return fmt.Errorf("fee schedule overflows at max amount: %w", err)
	}
	return nil
}

// EffectiveFeeMsat returns the provider's own fee for proxying an invoice of
// amount_msat, excluding the routing budget. It mirrors the calculation in
// wrap and is exposed so that the nostr layer can advertise it and so that
// clients can be compared on a like-for-like basis.
func (p RelayParameters) EffectiveFeeMsat(amount_msat uint64) uint64 {
	fee, err := p.effectiveFeeMsat(amount_msat)
	if err != nil {
		return math.MaxUint64
	}
	return fee
}

func (p RelayParameters) effectiveFeeMsat(amountMsat uint64) (uint64, error) {
	proportional, err := checkedMulDiv(amountMsat, p.RoutingFeePPM, 1_000_000)
	if err != nil {
		return 0, err
	}
	return checkedAdd(p.RoutingFeeBaseMsat, proportional)
}

func checkedAdd(a, b uint64) (uint64, error) {
	result, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return 0, fmt.Errorf("uint64 addition overflow")
	}
	return result, nil
}

func checkedMulDiv(a, b, divisor uint64) (uint64, error) {
	if divisor == 0 {
		return 0, fmt.Errorf("division by zero")
	}
	hi, lo := bits.Mul64(a, b)
	if hi >= divisor {
		return 0, fmt.Errorf("uint64 multiplication overflow")
	}
	quotient, _ := bits.Div64(hi, lo, divisor)
	return quotient, nil
}
