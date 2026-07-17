package nostr

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestLeadingZeroBits(t *testing.T) {
	tests := []struct {
		in   []byte
		want int
	}{
		{[]byte{0x00, 0x00, 0xff}, 16},
		{[]byte{0x0f, 0xff}, 4},
		{[]byte{0x80}, 0},
		{[]byte{0x00, 0x80}, 8},
		{[]byte{0x00, 0x00, 0x00, 0x00}, 32},
	}
	for _, tt := range tests {
		if got := leadingZeroBits(tt.in); got != tt.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseNetwork(t *testing.T) {
	valid := []string{"mainnet", "testnet", "signet", "regtest"}
	for _, s := range valid {
		n, err := ParseNetwork(s)
		if err != nil {
			t.Errorf("ParseNetwork(%q) unexpected error: %v", s, err)
		}
		if string(n) != s {
			t.Errorf("ParseNetwork(%q) = %q, want %q", s, n, s)
		}
	}
	invalid := []string{"", "Signet", "signet ", "simnet", "bitcoin"}
	for _, s := range invalid {
		if _, err := ParseNetwork(s); err == nil {
			t.Errorf("ParseNetwork(%q) expected error, got nil", s)
		}
	}
}

func TestAnnouncePoWMineAndVerify(t *testing.T) {
	// 32-byte x-only pubkey (hex).
	pub := "1111111111111111111111111111111111111111111111111111111111111111"
	const target = 12

	nonce, bitsGot, err := MineAnnouncePoW(pub, target, 1, 0)
	if err != nil {
		t.Fatalf("MineAnnouncePoW: %v", err)
	}
	if bitsGot < target {
		t.Fatalf("mined %d bits, want >= %d", bitsGot, target)
	}
	verified, err := AnnouncePoWBits(pub, nonce)
	if err != nil {
		t.Fatalf("AnnouncePoWBits: %v", err)
	}
	if verified != bitsGot {
		t.Fatalf("verify mismatch: mined %d, verified %d", bitsGot, verified)
	}
	if verified < target {
		t.Fatalf("verified %d bits below target %d", verified, target)
	}
}

func TestAnnouncePoWZeroNonce(t *testing.T) {
	pub := "1111111111111111111111111111111111111111111111111111111111111111"
	got, err := AnnouncePoWBits(pub, 0)
	if err != nil {
		t.Fatalf("AnnouncePoWBits: %v", err)
	}
	if got != 0 {
		t.Fatalf("AnnouncePoWBits(nonce=0) = %d, want 0", got)
	}
}

func TestOfferHelpers(t *testing.T) {
	o := Offer{
		BaseFeeMsat:   1000,
		FeePPM:        1000,
		MinAmountMsat: 10_000,
		MaxAmountMsat: 1_000_000,
		Features:      []string{FeaturePayBolt11, FeatureWrapBolt11},
	}
	if got := o.EffectiveFeeMsat(1_000_000); got != 2000 {
		t.Errorf("EffectiveFeeMsat = %d, want 2000", got)
	}
	if got := (Offer{BaseFeeMsat: math.MaxUint64, FeePPM: math.MaxUint64}).EffectiveFeeMsat(math.MaxUint64); got != math.MaxUint64 {
		t.Errorf("overflowing EffectiveFeeMsat = %d, want saturation", got)
	}
	if !o.HasFeature(FeatureWrapBolt11) {
		t.Error("expected HasFeature(wrap_bolt11) true")
	}
	if o.HasFeature(FeatureWrapBolt12) {
		t.Error("expected HasFeature(wrap_bolt12) false")
	}
	if !o.CanServe(500_000, FeatureWrapBolt11) {
		t.Error("expected CanServe(500_000, wrap_bolt11) true")
	}
	if o.CanServe(5_000, FeatureWrapBolt11) {
		t.Error("amount below min should not be servable")
	}
	if o.CanServe(2_000_000, FeatureWrapBolt11) {
		t.Error("amount above max should not be servable")
	}
	if o.CanServe(500_000, FeatureWrapBolt12) {
		t.Error("unsupported feature should not be servable")
	}
}

func TestWrapFeature(t *testing.T) {
	cases := map[string]string{
		"":               FeatureWrapBolt11,
		"bolt11":         FeatureWrapBolt11,
		"bolt11_blinded": FeatureWrapBolt11Blinded,
		"bolt12":         FeatureWrapBolt12,
	}
	for in, want := range cases {
		if got := WrapFeature(in); got != want {
			t.Errorf("WrapFeature(%q) = %q, want %q", in, got, want)
		}
	}
}

// signLNDStyle produces an LND-style zbase32 recoverable signature over the
// attestation message, the way a node would.
func signLNDStyle(t *testing.T, priv *btcec.PrivateKey, msg []byte) string {
	t.Helper()
	digest := chainhash.DoubleHashB(append([]byte(signedMsgPrefix), msg...))
	sig := ecdsa.SignCompact(priv, digest, true)
	return zbase32Encode(sig)
}

// zbase32Encode is the inverse of zbase32Decode, used only by tests.
func zbase32Encode(b []byte) string {
	var out []byte
	var buffer uint64
	var bitsLeft uint
	for _, x := range b {
		buffer = (buffer << 8) | uint64(x)
		bitsLeft += 8
		for bitsLeft >= 5 {
			bitsLeft -= 5
			out = append(out, zbase32Alphabet[(buffer>>bitsLeft)&0x1f])
		}
	}
	if bitsLeft > 0 {
		out = append(out, zbase32Alphabet[(buffer<<(5-bitsLeft))&0x1f])
	}
	return string(out)
}

func TestVerifyAttestation(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	nodePubkey := zbase32HexCompressed(priv)
	nostrPub := "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab"

	sig := signLNDStyle(t, priv, AttestationMessage(nostrPub))

	if err := VerifyAttestation(nostrPub, nodePubkey, sig); err != nil {
		t.Fatalf("VerifyAttestation valid sig: %v", err)
	}

	// Wrong nostr pubkey must fail (signature is over a different message).
	if err := VerifyAttestation("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", nodePubkey, sig); err == nil {
		t.Fatal("expected failure for mismatched nostr pubkey")
	}

	// Claiming a different node pubkey must fail.
	other, _ := btcec.NewPrivateKey()
	if err := VerifyAttestation(nostrPub, zbase32HexCompressed(other), sig); err == nil {
		t.Fatal("expected failure for mismatched node pubkey")
	}
}

func zbase32HexCompressed(priv *btcec.PrivateKey) string {
	return hexEncode(priv.PubKey().SerializeCompressed())
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}

func TestZbase32RoundTrip(t *testing.T) {
	in := []byte{0x00, 0x01, 0x02, 0xfe, 0xff, 0x7a, 0x55}
	encoded := zbase32Encode(in)
	decoded, err := zbase32Decode(encoded)
	if err != nil {
		t.Fatalf("zbase32Decode: %v", err)
	}
	// Decoding may yield trailing padding bits; compare the meaningful prefix.
	if len(decoded) < len(in) {
		t.Fatalf("decoded shorter than input: %d < %d", len(decoded), len(in))
	}
	for i := range in {
		if decoded[i] != in[i] {
			t.Fatalf("byte %d: got %02x want %02x", i, decoded[i], in[i])
		}
	}
}
