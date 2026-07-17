package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cretz/bine/control"
	"golang.org/x/net/proxy"
)

const (
	torControlTimeout = 10 * time.Second

	safeCookieServerKey = "Tor safe cookie authentication server-to-controller hash"
	safeCookieClientKey = "Tor safe cookie authentication controller-to-server hash"
)

type torConfig struct {
	Enabled         bool
	ProxyNostr      bool
	HiddenService   bool
	SOCKSAddress    string
	SOCKSUsername   string
	SOCKSPassword   string
	ControlAddress  string
	ControlPassword string
	ControlCookie   string
	TargetAddress   string
	VirtualPort     int
}

func logTorStartup(logger *log.Logger, cfg torConfig) {
	if !cfg.Enabled {
		logger.Println("tor: disabled; Nostr relay connections use direct network access")
		return
	}

	logger.Printf("tor: enabled; Nostr proxy=%t ephemeral hidden service=%t", cfg.ProxyNostr, cfg.HiddenService)
	if cfg.ProxyNostr {
		logger.Printf("tor: Nostr relay connections use SOCKS5 at %s (SOCKS credentials configured=%t, direct fallback disabled)", cfg.SOCKSAddress, cfg.SOCKSUsername != "")
	} else {
		logger.Println("tor: Nostr proxy disabled; Nostr relay connections use direct network access")
	}

	if cfg.HiddenService {
		authMethod := "SAFECOOKIE"
		if cfg.ControlPassword != "" {
			authMethod = "password"
		}
		cookieSource := ""
		if authMethod == "SAFECOOKIE" && cfg.ControlCookie != "" {
			cookieSource = " local-cookie=" + cfg.ControlCookie
		}
		logger.Printf("tor: control=%s authentication=%s%s; ephemeral v3 port %d targets %s", cfg.ControlAddress, authMethod, cookieSource, cfg.VirtualPort, cfg.TargetAddress)
	} else {
		logger.Println("tor: ephemeral hidden service disabled")
	}
}

func logAdvertisedURLs(logger *log.Logger, onionURL string, offerURLs []string) {
	if onionURL != "" {
		logger.Printf("tor: onion endpoint advertised in offer: %s", onionURL)
	}
	if len(offerURLs) == 0 {
		logger.Println("offer: no direct HTTP or onion URLs advertised")
		return
	}
	logger.Printf("offer: advertised direct URLs: %v", offerURLs)
}

func (c torConfig) validate(httpListen string) error {
	if !c.Enabled {
		return nil
	}
	if !c.ProxyNostr && !c.HiddenService {
		return fmt.Errorf("at least one of tor proxying or the hidden service must be enabled")
	}
	if c.ProxyNostr {
		if _, _, err := net.SplitHostPort(c.SOCKSAddress); err != nil {
			return fmt.Errorf("invalid tor SOCKS address %q: %w", c.SOCKSAddress, err)
		}
		if (c.SOCKSUsername == "") != (c.SOCKSPassword == "") {
			return fmt.Errorf("tor SOCKS username and password must be set together")
		}
	}
	if !c.HiddenService {
		return nil
	}
	if httpListen == "" {
		return fmt.Errorf("tor hidden service requires the direct HTTP listener")
	}
	if _, _, err := net.SplitHostPort(c.ControlAddress); err != nil {
		return fmt.Errorf("invalid tor control address %q: %w", c.ControlAddress, err)
	}
	if c.ControlPassword != "" && c.ControlCookie != "" {
		return fmt.Errorf("tor control password and cookie path are mutually exclusive")
	}
	if c.ControlCookie != "" && !filepath.IsAbs(c.ControlCookie) {
		return fmt.Errorf("tor control cookie path must be absolute")
	}
	if _, _, err := net.SplitHostPort(c.TargetAddress); err != nil {
		return fmt.Errorf("invalid tor hidden-service target %q: %w", c.TargetAddress, err)
	}
	if c.VirtualPort < 1 || c.VirtualPort > 65535 {
		return fmt.Errorf("tor hidden-service virtual port must be between 1 and 65535")
	}
	return nil
}

func defaultTorTarget(httpListen string) (string, error) {
	host, port, err := net.SplitHostPort(httpListen)
	if err != nil {
		return "", fmt.Errorf("invalid direct HTTP listen address %q: %w", httpListen, err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port), nil
}

func newTorHTTPClient(address, username, password string) (*http.Client, error) {
	var auth *proxy.Auth
	if username != "" || password != "" {
		auth = &proxy.Auth{User: username, Password: password}
	}
	forward := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	dialer, err := proxy.SOCKS5("tcp", address, auth, forward)
	if err != nil {
		return nil, fmt.Errorf("configure Tor SOCKS proxy: %w", err)
	}

	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			return contextDialer.DialContext(ctx, network, address)
		}
		return dialer.Dial(network, address)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}, nil
}

type ephemeralOnion struct {
	control   *control.Conn
	conn      net.Conn
	serviceID string
	closeOnce sync.Once
	closeErr  error
}

func createEphemeralOnion(ctx context.Context, cfg torConfig) (*ephemeralOnion, error) {
	dialer := net.Dialer{Timeout: torControlTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.ControlAddress)
	if err != nil {
		return nil, fmt.Errorf("connect to Tor control port: %w", err)
	}
	controller := control.NewConn(textproto.NewConn(conn))
	fail := func(err error) (*ephemeralOnion, error) {
		_ = controller.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(torControlTimeout)); err != nil {
		return fail(fmt.Errorf("set Tor control deadline: %w", err))
	}
	if err := authenticateTorControl(controller, cfg.ControlPassword, cfg.ControlCookie); err != nil {
		return fail(fmt.Errorf("authenticate with Tor control port: %w", err))
	}
	response, err := controller.AddOnion(&control.AddOnionRequest{
		Key:   control.GenKey(control.KeyAlgoED25519V3),
		Flags: []string{"DiscardPK"},
		Ports: []*control.KeyVal{
			control.NewKeyVal(strconv.Itoa(cfg.VirtualPort), cfg.TargetAddress),
		},
	})
	if err != nil {
		return fail(fmt.Errorf("create ephemeral onion service: %w", err))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(fmt.Errorf("clear Tor control deadline: %w", err))
	}
	if !validOnionServiceID(response.ServiceID) {
		return fail(fmt.Errorf("Tor returned invalid v3 service ID %q", response.ServiceID))
	}
	return &ephemeralOnion{control: controller, conn: conn, serviceID: response.ServiceID}, nil
}

func authenticateTorControl(controller *control.Conn, password, cookiePath string) error {
	if password != "" {
		if _, err := controller.SendRequest("AUTHENTICATE %s", hex.EncodeToString([]byte(password))); err != nil {
			return err
		}
		controller.Authenticated = true
		return nil
	}

	protocolInfo, err := controller.ProtocolInfo()
	if err != nil {
		return err
	}
	if protocolInfo.HasAuthMethod("NULL") {
		return fmt.Errorf("Tor control port offers unauthenticated NULL access; refusing to use it")
	}
	if !protocolInfo.HasAuthMethod("SAFECOOKIE") {
		return fmt.Errorf("Tor control port does not offer SAFECOOKIE authentication; configure cookie authentication or provide a control password")
	}
	if cookiePath == "" {
		cookiePath = protocolInfo.CookieFile
	}
	if cookiePath == "" {
		return fmt.Errorf("Tor control port did not report a SAFECOOKIE path and no local cookie path was configured")
	}
	cookie, err := os.ReadFile(cookiePath)
	if err != nil {
		return fmt.Errorf("read Tor control cookie %q: %w", cookiePath, err)
	}
	if len(cookie) != 32 {
		return fmt.Errorf("Tor control cookie %q must be 32 bytes, got %d", cookiePath, len(cookie))
	}

	var clientNonce [32]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return fmt.Errorf("generate Tor SAFECOOKIE client nonce: %w", err)
	}
	response, err := controller.SendRequest("AUTHCHALLENGE SAFECOOKIE %s", hex.EncodeToString(clientNonce[:]))
	if err != nil {
		return fmt.Errorf("request Tor SAFECOOKIE challenge: %w", err)
	}
	serverHash, serverNonce, err := parseSafeCookieChallenge(response.Reply)
	if err != nil {
		return err
	}
	expectedServerHash := safeCookieHMAC(safeCookieServerKey, cookie, clientNonce[:], serverNonce)
	if !hmac.Equal(serverHash, expectedServerHash) {
		return fmt.Errorf("Tor SAFECOOKIE server hash mismatch")
	}
	clientHash := safeCookieHMAC(safeCookieClientKey, cookie, clientNonce[:], serverNonce)
	if _, err := controller.SendRequest("AUTHENTICATE %s", hex.EncodeToString(clientHash)); err != nil {
		return fmt.Errorf("authenticate Tor SAFECOOKIE challenge: %w", err)
	}
	controller.Authenticated = true
	return nil
}

func parseSafeCookieChallenge(reply string) ([]byte, []byte, error) {
	fields := strings.Fields(reply)
	if len(fields) == 0 || fields[0] != "AUTHCHALLENGE" {
		return nil, nil, fmt.Errorf("invalid Tor SAFECOOKIE challenge response")
	}

	values := make(map[string]string, 2)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok || (key != "SERVERHASH" && key != "SERVERNONCE") {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return nil, nil, fmt.Errorf("duplicate Tor SAFECOOKIE %s field", key)
		}
		values[key] = value
	}
	serverHash, err := hex.DecodeString(values["SERVERHASH"])
	if err != nil || len(serverHash) != 32 {
		return nil, nil, fmt.Errorf("invalid Tor SAFECOOKIE server hash")
	}
	serverNonce, err := hex.DecodeString(values["SERVERNONCE"])
	if err != nil || len(serverNonce) != 32 {
		return nil, nil, fmt.Errorf("invalid Tor SAFECOOKIE server nonce")
	}
	return serverHash, serverNonce, nil
}

func safeCookieHMAC(key string, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

func validOnionServiceID(serviceID string) bool {
	if len(serviceID) != 56 {
		return false
	}
	for _, char := range serviceID {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			return false
		}
	}
	return true
}

func (s *ephemeralOnion) URL() string {
	return "http://" + s.serviceID + ".onion/spec"
}

// Watch checks that the control connection still owns the ephemeral service.
// Losing that connection removes the onion service, so the relay must stop
// advertising instead of continuing with a stale address.
func (s *ephemeralOnion) Watch(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.conn.SetDeadline(time.Now().Add(torControlTimeout)); err != nil {
				return fmt.Errorf("set Tor control health deadline: %w", err)
			}
			info, err := s.control.GetInfo("onions/current")
			if clearErr := s.conn.SetDeadline(time.Time{}); err == nil && clearErr != nil {
				err = clearErr
			}
			if err != nil {
				return fmt.Errorf("Tor control health check: %w", err)
			}
			found := false
			for _, entry := range info {
				if strings.Contains(entry.Val, s.serviceID) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Tor no longer reports ephemeral onion service %s.onion", s.serviceID)
			}
		}
	}
}

func (s *ephemeralOnion) Close() error {
	s.closeOnce.Do(func() {
		_ = s.conn.SetDeadline(time.Now().Add(torControlTimeout))
		if err := s.control.DelOnion(s.serviceID); err != nil {
			s.closeErr = fmt.Errorf("delete ephemeral onion service: %w", err)
		}
		if err := s.control.Close(); s.closeErr == nil && err != nil {
			s.closeErr = fmt.Errorf("close Tor control connection: %w", err)
		}
	})
	return s.closeErr
}
