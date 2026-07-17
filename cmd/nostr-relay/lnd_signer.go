package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lnproxy/lnc"
)

// nodeSigner is the narrow LND identity-key surface needed for nostr offer
// attestation. Keeping it local avoids requiring unpublished lnc extensions.
type nodeSigner interface {
	IdentityPubkey() (string, error)
	SignMessage([]byte) (string, error)
}

type lndSigner struct {
	lnd     *lnc.Lnd
	timeout time.Duration
}

func newLNDSigner(lnd *lnc.Lnd) *lndSigner {
	return &lndSigner{lnd: lnd, timeout: 15 * time.Second}
}

func (s *lndSigner) IdentityPubkey() (string, error) {
	req, err := s.request(http.MethodGet, "v1/getinfo", nil)
	if err != nil {
		return "", err
	}

	response := struct {
		IdentityPubkey string `json:"identity_pubkey"`
	}{}
	if err := s.do(req, &response); err != nil {
		return "", err
	}
	if response.IdentityPubkey == "" {
		return "", errors.New("v1/getinfo: empty identity_pubkey")
	}
	pubkey, err := hex.DecodeString(response.IdentityPubkey)
	if err != nil || len(pubkey) != 33 || (pubkey[0] != 2 && pubkey[0] != 3) {
		return "", errors.New("v1/getinfo: invalid identity_pubkey")
	}
	return strings.ToLower(response.IdentityPubkey), nil
}

func (s *lndSigner) SignMessage(message []byte) (string, error) {
	body, err := json.Marshal(struct {
		Message []byte `json:"msg"`
	}{Message: message})
	if err != nil {
		return "", err
	}
	req, err := s.request(http.MethodPost, "v1/signmessage", bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	response := struct {
		Signature string `json:"signature"`
	}{}
	if err := s.do(req, &response); err != nil {
		return "", err
	}
	const zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	if len(response.Signature) != 104 {
		return "", errors.New("v1/signmessage: invalid signature length")
	}
	for _, char := range response.Signature {
		if !strings.ContainsRune(zbase32Alphabet, char) {
			return "", errors.New("v1/signmessage: invalid zbase32 signature")
		}
	}
	return response.Signature, nil
}

func (s *lndSigner) request(method, path string, body io.Reader) (*http.Request, error) {
	if s.lnd == nil || s.lnd.Host == nil || s.lnd.Client == nil {
		return nil, errors.New("lnd host and client are required")
	}
	hostname := strings.ToLower(s.lnd.Host.Hostname())
	loopback := hostname == "localhost" || strings.HasSuffix(hostname, ".localhost")
	if ip := net.ParseIP(hostname); ip != nil {
		loopback = ip.IsLoopback()
	}
	if s.lnd.Host.Scheme != "https" && !(s.lnd.Host.Scheme == "http" && loopback) {
		return nil, errors.New("authenticated lnd REST requests require HTTPS or a loopback HTTP endpoint")
	}
	req, err := http.NewRequest(method, s.lnd.Host.JoinPath(path).String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Grpc-Metadata-macaroon", s.lnd.Macaroon)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (s *lndSigner) do(req *http.Request, response any) error {
	ctx := req.Context()
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	req = req.WithContext(ctx)
	client := *s.lnd.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, (4<<10)+1))
		if readErr != nil {
			return readErr
		}
		return fmt.Errorf("%s: HTTP %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
	if err != nil {
		return err
	}
	if len(body) > 16<<10 {
		return errors.New("lnd attestation response too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(response); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("lnd attestation response contains multiple JSON values")
		}
		return err
	}
	return nil
}
