package main

import (
	"testing"
	"time"
)

func TestEnvInt(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		if got, err := envInt("LNPROXY_TEST_INT", 8); err != nil || got != 8 {
			t.Fatalf("envInt() = %d, %v, want 8, nil", got, err)
		}
	})
	t.Run("environment", func(t *testing.T) {
		t.Setenv("LNPROXY_TEST_INT", "12")
		if got, err := envInt("LNPROXY_TEST_INT", 8); err != nil || got != 12 {
			t.Fatalf("envInt() = %d, %v, want 12, nil", got, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv("LNPROXY_TEST_INT", "invalid")
		if _, err := envInt("LNPROXY_TEST_INT", 8); err == nil {
			t.Fatal("envInt() accepted an invalid integer")
		}
	})
}

func TestEnvDuration(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		if got, err := envDuration("LNPROXY_TEST_DURATION", time.Second); err != nil || got != time.Second {
			t.Fatalf("envDuration() = %s, %v, want 1s, nil", got, err)
		}
	})
	t.Run("environment", func(t *testing.T) {
		t.Setenv("LNPROXY_TEST_DURATION", "250ms")
		if got, err := envDuration("LNPROXY_TEST_DURATION", time.Second); err != nil || got != 250*time.Millisecond {
			t.Fatalf("envDuration() = %s, %v, want 250ms, nil", got, err)
		}
	})
	t.Run("negative", func(t *testing.T) {
		t.Setenv("LNPROXY_TEST_DURATION", "-1s")
		if got, err := envDuration("LNPROXY_TEST_DURATION", time.Second); err != nil || got != -time.Second {
			t.Fatalf("envDuration() = %s, %v, want -1s, nil", got, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv("LNPROXY_TEST_DURATION", "invalid")
		if _, err := envDuration("LNPROXY_TEST_DURATION", time.Second); err == nil {
			t.Fatal("envDuration() accepted an invalid duration")
		}
	})
}

func TestEnvBool(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		if got, err := envBool("LNPROXY_TEST_BOOL", true); err != nil || !got {
			t.Fatalf("envBool() = %t, %v, want true, nil", got, err)
		}
	})
	t.Run("environment", func(t *testing.T) {
		t.Setenv("LNPROXY_TEST_BOOL", "false")
		if got, err := envBool("LNPROXY_TEST_BOOL", true); err != nil || got {
			t.Fatalf("envBool() = %t, %v, want false, nil", got, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv("LNPROXY_TEST_BOOL", "sometimes")
		if _, err := envBool("LNPROXY_TEST_BOOL", true); err == nil {
			t.Fatal("envBool() accepted an invalid boolean")
		}
	})
}
