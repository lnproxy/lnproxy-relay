package relay

import (
	"math"
	"testing"
)

func TestEffectiveFeeMsat(t *testing.T) {
	p := RelayParameters{RoutingFeeBaseMsat: 1000, RoutingFeePPM: 1000}
	// base 1000 + 0.1% of 1_000_000 = 1000 + 1000 = 2000
	if got := p.EffectiveFeeMsat(1_000_000); got != 2000 {
		t.Fatalf("EffectiveFeeMsat = %d, want 2000", got)
	}
	// zero amount -> just base
	if got := p.EffectiveFeeMsat(0); got != 1000 {
		t.Fatalf("EffectiveFeeMsat(0) = %d, want 1000", got)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		p       RelayParameters
		wantErr bool
	}{
		{"ok", RelayParameters{MinAmountMsat: 1000, MaxAmountMsat: 2000, MaxExpiry: 3600, MaxActiveCircuits: 1}, false},
		{"zero min", RelayParameters{MinAmountMsat: 0, MaxAmountMsat: 2000, MaxExpiry: 3600, MaxActiveCircuits: 1}, true},
		{"max below min", RelayParameters{MinAmountMsat: 2000, MaxAmountMsat: 1000, MaxExpiry: 3600, MaxActiveCircuits: 1}, true},
		{"zero max expiry", RelayParameters{MinAmountMsat: 1000, MaxAmountMsat: 2000}, true},
		{"overflowing fee", RelayParameters{MinAmountMsat: 1000, MaxAmountMsat: math.MaxUint64, MaxExpiry: 3600, RoutingFeePPM: math.MaxUint64}, true},
		{"equal bounds", RelayParameters{MinAmountMsat: 1000, MaxAmountMsat: 1000, MaxExpiry: 3600, MaxActiveCircuits: 1}, false},
		{"omitted active circuit limit", RelayParameters{MinAmountMsat: 1000, MaxAmountMsat: 2000, MaxExpiry: 3600}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	p := NewRelay(nil).RelayParameters
	t.Setenv("LNPROXY_MIN_MSAT", "5000")
	t.Setenv("LNPROXY_MAX_MSAT", "2000000000")
	t.Setenv("LNPROXY_BASE_FEE_MSAT", "2000")
	t.Setenv("LNPROXY_FEE_PPM", "500")
	t.Setenv("LNPROXY_MAX_EXPIRY", "86400")
	t.Setenv("LNPROXY_MAX_ACTIVE_CIRCUITS", "64")

	if err := p.ApplyEnvOverrides(); err != nil {
		t.Fatalf("ApplyEnvOverrides: %v", err)
	}
	if p.MinAmountMsat != 5000 {
		t.Errorf("MinAmountMsat = %d, want 5000", p.MinAmountMsat)
	}
	if p.MaxAmountMsat != 2_000_000_000 {
		t.Errorf("MaxAmountMsat = %d, want 2000000000", p.MaxAmountMsat)
	}
	if p.RoutingFeeBaseMsat != 2000 {
		t.Errorf("RoutingFeeBaseMsat = %d, want 2000", p.RoutingFeeBaseMsat)
	}
	if p.RoutingFeePPM != 500 {
		t.Errorf("RoutingFeePPM = %d, want 500", p.RoutingFeePPM)
	}
	if p.MaxExpiry != 86400 {
		t.Errorf("MaxExpiry = %d, want 86400", p.MaxExpiry)
	}
	if p.MaxActiveCircuits != 64 {
		t.Errorf("MaxActiveCircuits = %d, want 64", p.MaxActiveCircuits)
	}
}

func TestApplyEnvOverridesKeepsDefaults(t *testing.T) {
	p := NewRelay(nil).RelayParameters
	orig := p
	// No env set: values must be unchanged.
	if err := p.ApplyEnvOverrides(); err != nil {
		t.Fatalf("ApplyEnvOverrides: %v", err)
	}
	if p != orig {
		t.Fatalf("ApplyEnvOverrides changed parameters with no env set: %+v != %+v", p, orig)
	}
}

func TestApplyEnvOverridesInvalid(t *testing.T) {
	p := NewRelay(nil).RelayParameters
	t.Setenv("LNPROXY_MAX_MSAT", "not-a-number")
	if err := p.ApplyEnvOverrides(); err == nil {
		t.Fatal("expected error for invalid LNPROXY_MAX_MSAT, got nil")
	}
}
