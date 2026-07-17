// Package nostr implements decentralized lnproxy provider discovery and the
// encrypted wrap request/response transport described in the spec repository's
// nostr.md (kinds 38421/21821/21822).
//
// It is intentionally transport-only: all invoice logic stays in the parent
// relay package, which this package drives through relay.Relay.OpenCircuit.
package nostr

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// Protocol constants, matching spec/nostr.md.
const (
	KindOffer    = 38421 // addressable provider advertisement
	KindRequest  = 21821 // ephemeral encrypted wrap request
	KindResponse = 21822 // ephemeral encrypted wrap response

	ProtocolVersion = "lnproxy-v1" // value of the offer 'd' tag

	// AnnouncePoWPrefix is prepended to the nostr pubkey when computing the
	// optional anonymous identity proof of work.
	AnnouncePoWPrefix = "lnproxy"

	// attestationContext is signed by the LN node to bind it to a nostr
	// identity. The nostr pubkey hex is appended.
	attestationContext = "lnproxy:v1:announce:"
)

// Network is the bitcoin network an offer applies to. It is the value of the
// offer 'n' tag.
type Network string

const (
	Mainnet Network = "mainnet"
	Testnet Network = "testnet"
	Signet  Network = "signet"
	Regtest Network = "regtest"
)

// ParseNetwork validates an operator-supplied network name and returns the
// corresponding Network. Unknown values are rejected so that a typo does not
// silently publish offers that no client filter will ever match (clients
// filter offers on the exact 'n' tag value).
func ParseNetwork(s string) (Network, error) {
	switch n := Network(s); n {
	case Mainnet, Testnet, Signet, Regtest:
		return n, nil
	default:
		return "", fmt.Errorf("unknown network %q (must be one of: mainnet, testnet, signet, regtest)", s)
	}
}

// Feature flags advertised in an offer's "features" array.
const (
	FeaturePayBolt11         = "pay_bolt11"
	FeaturePayBolt11Blinded  = "pay_bolt11_blinded"
	FeatureWrapBolt11        = "wrap_bolt11"
	FeatureWrapBolt11Blinded = "wrap_bolt11_blinded"
	FeaturePayBolt12         = "pay_bolt12"
	FeatureWrapBolt12        = "wrap_bolt12"
	FeatureRequestIDV1       = "request_id_v1"
)

// Offer is the JSON content of a kind 38421 advertisement.
type Offer struct {
	BaseFeeMsat      uint64   `json:"base_fee_msat"`
	FeePPM           uint64   `json:"fee_ppm"`
	MinAmountMsat    uint64   `json:"min_amount_msat"`
	MaxAmountMsat    uint64   `json:"max_amount_msat"`
	MaxExpirySeconds uint64   `json:"max_expiry_seconds"`
	MinRequestPoW    int      `json:"min_request_pow"`
	Features         []string `json:"features"`
	Relays           []string `json:"relays"`
	URLs             []string `json:"urls,omitempty"`
	NodePubkey       string   `json:"node_pubkey,omitempty"`
	NodeSig          string   `json:"node_sig,omitempty"`
	PoWNonce         string   `json:"pow_nonce,omitempty"`
}

// EffectiveFeeMsat returns the provider's advertised fee for proxying an
// invoice of amount_msat, used by clients to sort offers cheapest-first.
func (o Offer) EffectiveFeeMsat(amount_msat uint64) uint64 {
	hi, lo := bits.Mul64(amount_msat, o.FeePPM)
	if hi >= 1_000_000 {
		return math.MaxUint64
	}
	proportional, _ := bits.Div64(hi, lo, 1_000_000)
	fee, carry := bits.Add64(o.BaseFeeMsat, proportional, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return fee
}

// HasFeature reports whether the offer advertises the given feature flag.
func (o Offer) HasFeature(feature string) bool {
	for _, f := range o.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// CanServe reports whether the offer can wrap an invoice of amount_msat into
// the requested output format (one of the wrap_* features).
func (o Offer) CanServe(amount_msat uint64, wrapFeature string) bool {
	if amount_msat < o.MinAmountMsat || amount_msat > o.MaxAmountMsat {
		return false
	}
	return o.HasFeature(wrapFeature)
}

// AttestationMessage returns the exact bytes an LN node must sign to attest
// ownership of the nostr identity pubkeyHex.
func AttestationMessage(pubkeyHex string) []byte {
	return []byte(attestationContext + pubkeyHex)
}

// AnnouncePoWBits returns the number of leading zero bits of
// SHA256("lnproxy" || pubkey || nonce), the optional anonymous identity proof
// of work. pubkeyHex is the 32-byte x-only nostr public key in hex and nonce is
// interpreted as a 32-byte big-endian integer. A nonce of zero yields 0 bits.
func AnnouncePoWBits(pubkeyHex string, nonce uint64) (int, error) {
	if nonce == 0 {
		return 0, nil
	}
	pub, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return 0, fmt.Errorf("invalid pubkey hex: %w", err)
	}
	if len(pub) != 32 {
		return 0, fmt.Errorf("pubkey must be 32 bytes, got %d", len(pub))
	}
	h := sha256.New()
	h.Write([]byte(AnnouncePoWPrefix))
	h.Write(pub)
	var nb [32]byte
	binary.BigEndian.PutUint64(nb[24:], nonce)
	h.Write(nb[:])
	return leadingZeroBits(h.Sum(nil)), nil
}

// MineAnnouncePoW searches for a nonce such that AnnouncePoWBits >= target,
// returning the first matching nonce. It scans nonces starting from start and
// stops after at most limit attempts (limit == 0 means no limit). It is used
// once per identity by anonymous providers; honest providers may also raise
// their ranking by mining more bits.
func MineAnnouncePoW(pubkeyHex string, target int, start, limit uint64) (uint64, int, error) {
	pub, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid pubkey hex: %w", err)
	}
	if len(pub) != 32 {
		return 0, 0, fmt.Errorf("pubkey must be 32 bytes, got %d", len(pub))
	}
	prefix := append([]byte(AnnouncePoWPrefix), pub...)
	var nb [32]byte
	for i := uint64(0); limit == 0 || i < limit; i++ {
		nonce := start + i
		if nonce == 0 {
			continue
		}
		h := sha256.New()
		h.Write(prefix)
		binary.BigEndian.PutUint64(nb[24:], nonce)
		h.Write(nb[:])
		if leadingZeroBits(h.Sum(nil)) >= target {
			bitsGot, _ := AnnouncePoWBits(pubkeyHex, nonce)
			return nonce, bitsGot, nil
		}
	}
	return 0, 0, errors.New("proof of work not found within limit")
}

// leadingZeroBits counts the leading zero bits of a big-endian byte slice.
func leadingZeroBits(b []byte) int {
	count := 0
	for _, x := range b {
		if x == 0 {
			count += 8
			continue
		}
		count += bits.LeadingZeros8(x)
		break
	}
	return count
}
