package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lnproxy/lnc"
)

var (
	testNodePubkey    = "02" + strings.Repeat("ab", 32)
	testNodeSignature = strings.Repeat("y", 104)
)

func testSigner(t *testing.T, handler http.HandlerFunc) *lndSigner {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	host, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return newLNDSigner(&lnc.Lnd{
		Host:      host,
		Client:    server.Client(),
		TlsConfig: &tls.Config{},
		Macaroon:  "test-macaroon",
	})
}

func TestLNDSignerIdentityPubkey(t *testing.T) {
	signer := testSigner(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/getinfo" {
			t.Errorf("path = %q, want /v1/getinfo", req.URL.Path)
		}
		if got := req.Header.Get("Grpc-Metadata-macaroon"); got != "test-macaroon" {
			t.Errorf("macaroon = %q, want test-macaroon", got)
		}
		json.NewEncoder(w).Encode(map[string]string{"identity_pubkey": testNodePubkey})
	})

	pubkey, err := signer.IdentityPubkey()
	if err != nil {
		t.Fatal(err)
	}
	if pubkey != testNodePubkey {
		t.Fatalf("pubkey = %q, want %q", pubkey, testNodePubkey)
	}
}

func TestLNDSignerSignMessage(t *testing.T) {
	message := []byte("lnproxy:v1:announce:test")
	signer := testSigner(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/signmessage" {
			t.Errorf("path = %q, want /v1/signmessage", req.URL.Path)
		}
		var body struct {
			Message string `json:"msg"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Message != base64.StdEncoding.EncodeToString(message) {
			t.Errorf("message = %q, want base64 payload", body.Message)
		}
		json.NewEncoder(w).Encode(map[string]string{"signature": testNodeSignature})
	})

	signature, err := signer.SignMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	if signature != testNodeSignature {
		t.Fatalf("signature = %q, want valid signature", signature)
	}
}

func TestLNDSignerRejectsHTTPError(t *testing.T) {
	signer := testSigner(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	})
	if _, err := signer.IdentityPubkey(); err == nil {
		t.Fatal("IdentityPubkey() error = nil, want HTTP error")
	}
}

func TestLNDSignerTimesOut(t *testing.T) {
	signer := testSigner(t, func(_ http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	})
	signer.timeout = 10 * time.Millisecond
	if _, err := signer.IdentityPubkey(); err == nil {
		t.Fatal("IdentityPubkey() error = nil, want timeout")
	}
}
