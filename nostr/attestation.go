package nostr

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// signedMsgPrefix is prepended by LND (and lnproxy clients) before hashing a
// message for signing, matching lnrpc.Lightning/SignMessage.
const signedMsgPrefix = "Lightning Signed Message:"

// VerifyAttestation checks that sig is a valid LND-style zbase32 recoverable
// signature over AttestationMessage(nostrPubkeyHex) and that the recovered
// public key equals nodePubkeyHex (hex compressed secp256k1 key). It returns
// nil on success.
//
// This is the verification half of the node attestation in spec/nostr.md: it
// proves that the LN node nodePubkeyHex authorized the nostr identity
// nostrPubkeyHex, without trusting any third party.
func VerifyAttestation(nostrPubkeyHex, nodePubkeyHex, sig string) error {
	if nodePubkeyHex == "" || sig == "" {
		return errors.New("missing node pubkey or signature")
	}
	sigBytes, err := zbase32Decode(sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	msg := AttestationMessage(nostrPubkeyHex)
	digest := chainhash.DoubleHashB(append([]byte(signedMsgPrefix), msg...))

	pub, _, err := ecdsa.RecoverCompact(sigBytes, digest)
	if err != nil {
		return fmt.Errorf("recover pubkey: %w", err)
	}
	recovered := fmt.Sprintf("%x", pub.SerializeCompressed())
	if recovered != nodePubkeyHex {
		return fmt.Errorf("attestation key mismatch: signed by %s, claimed %s", recovered, nodePubkeyHex)
	}
	return nil
}

// zbase32 alphabet used by LND for signmessage output.
const zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

var zbase32Reverse = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(zbase32Alphabet); i++ {
		t[zbase32Alphabet[i]] = int8(i)
	}
	return t
}()

// zbase32Decode decodes a zbase32 string (as produced by lncli signmessage).
func zbase32Decode(s string) ([]byte, error) {
	var out bytes.Buffer
	var buffer uint64
	var bitsLeft uint
	for i := 0; i < len(s); i++ {
		v := zbase32Reverse[s[i]]
		if v < 0 {
			return nil, fmt.Errorf("invalid zbase32 character %q", s[i])
		}
		buffer = (buffer << 5) | uint64(v)
		bitsLeft += 5
		if bitsLeft >= 8 {
			bitsLeft -= 8
			out.WriteByte(byte(buffer >> bitsLeft))
		}
	}
	return out.Bytes(), nil
}
