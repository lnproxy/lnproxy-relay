package nostr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

// Identity is a persistent provider nostr keypair.
type Identity struct {
	SecretKey string
	PublicKey string
}

// LoadOrCreateIdentity reads a hex nostr secret key from path, creating a new
// random one (0600) if the file does not exist. The matching x-only public key
// is derived. The persistent identity lets a provider accrue reputation across
// restarts.
func LoadOrCreateIdentity(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		sk := strings.TrimSpace(string(data))
		pk, err := nostr.GetPublicKey(sk)
		if err != nil {
			return Identity{}, err
		}
		return Identity{SecretKey: sk, PublicKey: pk}, nil
	case errors.Is(err, os.ErrNotExist):
		sk := nostr.GeneratePrivateKey()
		if sk == "" {
			return Identity{}, errors.New("failed to generate nostr private key")
		}
		pk, err := nostr.GetPublicKey(sk)
		if err != nil {
			return Identity{}, err
		}
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return Identity{}, err
			}
		}
		if err := os.WriteFile(path, []byte(sk+"\n"), 0o600); err != nil {
			return Identity{}, err
		}
		return Identity{SecretKey: sk, PublicKey: pk}, nil
	default:
		return Identity{}, err
	}
}
