package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
)

func TestTorConfigValidate(t *testing.T) {
	valid := torConfig{
		Enabled:        true,
		ProxyNostr:     true,
		HiddenService:  true,
		SOCKSAddress:   "127.0.0.1:9050",
		ControlAddress: "127.0.0.1:9051",
		TargetAddress:  "127.0.0.1:4747",
		VirtualPort:    80,
	}
	tests := []struct {
		name       string
		configure  func(*torConfig)
		httpListen string
		wantErr    string
	}{
		{name: "valid", httpListen: "127.0.0.1:4747"},
		{name: "disabled", configure: func(c *torConfig) { c.Enabled = false }, wantErr: ""},
		{name: "no feature", configure: func(c *torConfig) { c.ProxyNostr = false; c.HiddenService = false }, httpListen: "127.0.0.1:4747", wantErr: "at least one"},
		{name: "bad socks", configure: func(c *torConfig) { c.SOCKSAddress = "localhost" }, httpListen: "127.0.0.1:4747", wantErr: "SOCKS address"},
		{name: "partial socks auth", configure: func(c *torConfig) { c.SOCKSUsername = "relay" }, httpListen: "127.0.0.1:4747", wantErr: "set together"},
		{name: "missing listener", httpListen: "", wantErr: "requires the direct HTTP listener"},
		{name: "ambiguous control auth", configure: func(c *torConfig) { c.ControlPassword = "secret"; c.ControlCookie = "/run/tor/cookie" }, httpListen: "127.0.0.1:4747", wantErr: "mutually exclusive"},
		{name: "relative control cookie", configure: func(c *torConfig) { c.ControlCookie = "control_auth_cookie" }, httpListen: "127.0.0.1:4747", wantErr: "must be absolute"},
		{name: "bad target", configure: func(c *torConfig) { c.TargetAddress = "relay" }, httpListen: "127.0.0.1:4747", wantErr: "hidden-service target"},
		{name: "bad virtual port", configure: func(c *torConfig) { c.VirtualPort = 0 }, httpListen: "127.0.0.1:4747", wantErr: "between 1 and 65535"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			if test.configure != nil {
				test.configure(&cfg)
			}
			err := cfg.validate(test.httpListen)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestLogTorStartup(t *testing.T) {
	tests := []struct {
		name string
		cfg  torConfig
		want []string
	}{
		{
			name: "disabled",
			want: []string{
				"tor: disabled; Nostr relay connections use direct network access",
			},
		},
		{
			name: "proxy and onion",
			cfg: torConfig{
				Enabled:         true,
				ProxyNostr:      true,
				HiddenService:   true,
				SOCKSAddress:    "tor:9050",
				SOCKSUsername:   "isolation-user",
				SOCKSPassword:   "do-not-log",
				ControlAddress:  "tor:9051",
				ControlPassword: "also-do-not-log",
				TargetAddress:   "lnproxy:4747",
				VirtualPort:     80,
			},
			want: []string{
				"tor: enabled; Nostr proxy=true ephemeral hidden service=true",
				"tor: Nostr relay connections use SOCKS5 at tor:9050 (SOCKS credentials configured=true, direct fallback disabled)",
				"tor: control=tor:9051 authentication=password; ephemeral v3 port 80 targets lnproxy:4747",
			},
		},
		{
			name: "SAFECOOKIE override",
			cfg: torConfig{
				Enabled:        true,
				HiddenService:  true,
				ControlAddress: "tor:9051",
				ControlCookie:  "/var/run/tor/control_auth_cookie",
				TargetAddress:  "lnproxy:4747",
				VirtualPort:    80,
			},
			want: []string{
				"tor: control=tor:9051 authentication=SAFECOOKIE local-cookie=/var/run/tor/control_auth_cookie; ephemeral v3 port 80 targets lnproxy:4747",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := log.New(&output, "", 0)
			logTorStartup(logger, test.cfg)
			got := output.String()
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("startup log missing %q:\n%s", want, got)
				}
			}
			for _, secret := range []string{
				test.cfg.SOCKSUsername,
				test.cfg.SOCKSPassword,
				test.cfg.ControlPassword,
			} {
				if secret != "" && strings.Contains(got, secret) {
					t.Errorf("startup log exposed secret %q", secret)
				}
			}
		})
	}
}

func TestLogAdvertisedURLs(t *testing.T) {
	var output bytes.Buffer
	logger := log.New(&output, "", 0)
	logAdvertisedURLs(logger, "http://example.onion/spec", []string{
		"https://relay.example/spec",
		"http://example.onion/spec",
	})

	got := output.String()
	for _, want := range []string{
		"tor: onion endpoint advertised in offer: http://example.onion/spec",
		"offer: advertised direct URLs: [https://relay.example/spec http://example.onion/spec]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("startup log missing %q:\n%s", want, got)
		}
	}
}

func TestSafeCookieHMACVectors(t *testing.T) {
	sequence, err := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f" +
			"101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f" +
			"303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f" +
			"505152535455565758595a5b5c5d5e5f",
	)
	if err != nil {
		t.Fatal(err)
	}
	cookie, clientNonce, serverNonce := sequence[:32], sequence[32:64], sequence[64:]

	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "server", key: safeCookieServerKey, want: "3c8780ab52365c0d080750447e5f64dabc00428c6c434579c2043e18c1f85389"},
		{name: "client", key: safeCookieClientKey, want: "b47642df2d5abb84f69e6d02d41bed6b44aee33e69562528a82166fc98bc0b1e"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hex.EncodeToString(safeCookieHMAC(test.key, cookie, clientNonce, serverNonce))
			if got != test.want {
				t.Fatalf("SAFECOOKIE HMAC = %s, want %s", got, test.want)
			}
		})
	}
}

func TestParseSafeCookieChallenge(t *testing.T) {
	hash := strings.Repeat("01", 32)
	nonce := strings.Repeat("a2", 32)
	tests := []struct {
		name    string
		reply   string
		wantErr string
	}{
		{name: "valid", reply: "AUTHCHALLENGE SERVERHASH=" + hash + " SERVERNONCE=" + nonce + " FUTURE=value"},
		{name: "missing marker", reply: "SERVERHASH=" + hash + " SERVERNONCE=" + nonce, wantErr: "challenge response"},
		{name: "missing hash", reply: "AUTHCHALLENGE SERVERNONCE=" + nonce, wantErr: "server hash"},
		{name: "short nonce", reply: "AUTHCHALLENGE SERVERHASH=" + hash + " SERVERNONCE=aa", wantErr: "server nonce"},
		{name: "duplicate hash", reply: "AUTHCHALLENGE SERVERHASH=" + hash + " SERVERHASH=" + hash + " SERVERNONCE=" + nonce, wantErr: "duplicate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseSafeCookieChallenge(test.reply)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("parseSafeCookieChallenge() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("parseSafeCookieChallenge() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestDefaultTorTargetUsesLoopbackForWildcardListener(t *testing.T) {
	tests := map[string]string{
		":4747":        "127.0.0.1:4747",
		"0.0.0.0:4747": "127.0.0.1:4747",
		"[::]:4747":    "[::1]:4747",
	}
	for listen, want := range tests {
		t.Run(listen, func(t *testing.T) {
			target, err := defaultTorTarget(listen)
			if err != nil {
				t.Fatalf("defaultTorTarget: %v", err)
			}
			if target != want {
				t.Fatalf("target = %q, want %q", target, want)
			}
		})
	}
}

func TestTorHTTPClientUsesSOCKSHostnameAndAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		result <- serveSOCKSHandshake(conn, "relay-user", "relay-pass", "relay.example", 443)
	}()

	client, err := newTorHTTPClient(listener.Addr().String(), "relay-user", "relay-pass")
	if err != nil {
		t.Fatalf("newTorHTTPClient: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	conn, err := transport.DialContext(context.Background(), "tcp", "relay.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestNostrRelayUsesTorHTTPClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		result <- serveSOCKSHandshake(conn, "relay-user", "relay-pass", "relay.invalid", 443)
	}()

	torClient, err := newTorHTTPClient(listener.Addr().String(), "relay-user", "relay-pass")
	if err != nil {
		t.Fatalf("newTorHTTPClient: %v", err)
	}
	originalClient := http.DefaultClient
	http.DefaultClient = torClient
	t.Cleanup(func() { http.DefaultClient = originalClient })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	relay, err := gonostr.RelayConnect(ctx, "wss://relay.invalid")
	if relay != nil {
		relay.Close()
	}
	if err == nil {
		t.Fatal("RelayConnect unexpectedly completed against the SOCKS handshake stub")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("go-nostr did not dial the configured Tor SOCKS proxy")
	}
}

func serveSOCKSHandshake(conn net.Conn, username, password, host string, port uint16) error {
	var greeting [4]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting != [4]byte{5, 2, 0, 2} {
		return fmt.Errorf("SOCKS greeting = %v", greeting)
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return err
	}

	var authHeader [2]byte
	if _, err := io.ReadFull(conn, authHeader[:]); err != nil {
		return err
	}
	if authHeader[0] != 1 {
		return fmt.Errorf("SOCKS auth version = %d", authHeader[0])
	}
	user := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return err
	}
	pass := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	if string(user) != username || string(pass) != password {
		return fmt.Errorf("SOCKS credentials = %q:%q", user, pass)
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return err
	}

	var requestHeader [5]byte
	if _, err := io.ReadFull(conn, requestHeader[:]); err != nil {
		return err
	}
	if requestHeader[0] != 5 || requestHeader[1] != 1 || requestHeader[3] != 3 {
		return fmt.Errorf("SOCKS request header = %v", requestHeader)
	}
	domain := make([]byte, int(requestHeader[4]))
	if _, err := io.ReadFull(conn, domain); err != nil {
		return err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return err
	}
	if string(domain) != host || binary.BigEndian.Uint16(portBytes[:]) != port {
		return fmt.Errorf("SOCKS target = %s:%d", domain, binary.BigEndian.Uint16(portBytes[:]))
	}
	_, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	return err
}

func TestCreateEphemeralOnionAuthenticationAndCleanup(t *testing.T) {
	tests := []struct {
		name     string
		password string
		cookie   bool
	}{
		{name: "control password", password: "control-secret"},
		{name: "SAFECOOKIE", cookie: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cookiePath := ""
			var cookie []byte
			if test.cookie {
				cookiePath = t.TempDir() + "/control_auth_cookie"
				cookie = []byte("01234567890123456789012345678901")
				if err := os.WriteFile(cookiePath, cookie, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			address, commands, stop := startFakeTorControl(t, test.password, cookiePath, cookie, false)
			defer stop()

			cfg := torConfig{
				ControlAddress:  address,
				ControlPassword: test.password,
				TargetAddress:   "127.0.0.1:4747",
				VirtualPort:     80,
			}
			service, err := createEphemeralOnion(context.Background(), cfg)
			if err != nil {
				t.Fatalf("createEphemeralOnion: %v", err)
			}
			if got, want := service.URL(), "http://"+strings.Repeat("a", 56)+".onion/spec"; got != want {
				t.Fatalf("URL = %q, want %q", got, want)
			}
			if err := service.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			got := <-commands
			if !strings.Contains(got, "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:4747") {
				t.Fatalf("commands do not contain hardened ADD_ONION: %s", got)
			}
			if !strings.Contains(got, "DEL_ONION "+strings.Repeat("a", 56)) {
				t.Fatalf("commands do not contain DEL_ONION: %s", got)
			}
			if strings.Contains(got, "PrivateKey") {
				t.Fatalf("commands unexpectedly requested or logged a private key: %s", got)
			}
		})
	}
}

func TestCreateEphemeralOnionUsesLocalCookiePathOverride(t *testing.T) {
	localCookiePath := t.TempDir() + "/control_auth_cookie"
	cookie := []byte("01234567890123456789012345678901")
	if err := os.WriteFile(localCookiePath, cookie, 0o600); err != nil {
		t.Fatal(err)
	}
	address, _, stop := startFakeTorControl(
		t,
		"",
		"/data/.tor/control_auth_cookie",
		cookie,
		false,
	)
	defer stop()

	service, err := createEphemeralOnion(context.Background(), torConfig{
		ControlAddress: address,
		ControlCookie:  localCookiePath,
		TargetAddress:  "127.0.0.1:4747",
		VirtualPort:    80,
	})
	if err != nil {
		t.Fatalf("createEphemeralOnion with local cookie override: %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestCreateEphemeralOnionRejectsWrongLocalCookie(t *testing.T) {
	localCookiePath := t.TempDir() + "/control_auth_cookie"
	if err := os.WriteFile(localCookiePath, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	address, _, stop := startFakeTorControl(
		t,
		"",
		"/tor/control_auth_cookie",
		[]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		false,
	)
	defer stop()

	_, err := createEphemeralOnion(context.Background(), torConfig{
		ControlAddress: address,
		ControlCookie:  localCookiePath,
		TargetAddress:  "127.0.0.1:4747",
		VirtualPort:    80,
	})
	if err == nil || !strings.Contains(err.Error(), "server hash mismatch") {
		t.Fatalf("createEphemeralOnion() error = %v, want server hash mismatch", err)
	}
}

func TestCreateEphemeralOnionRejectsUnauthenticatedControlPort(t *testing.T) {
	address, _, stop := startFakeTorControl(t, "", "", nil, true)
	defer stop()

	_, err := createEphemeralOnion(context.Background(), torConfig{
		ControlAddress: address,
		TargetAddress:  "127.0.0.1:4747",
		VirtualPort:    80,
	})
	if err == nil || !strings.Contains(err.Error(), "unauthenticated NULL access") {
		t.Fatalf("createEphemeralOnion() error = %v, want NULL authentication rejection", err)
	}
}

func startFakeTorControl(t *testing.T, password, cookiePath string, cookie []byte, allowNull bool) (string, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	commands := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var seen []string
		var expectedCookieAuth string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			seen = append(seen, line)
			switch {
			case line == "PROTOCOLINFO" || line == "PROTOCOLINFO 1":
				if allowNull {
					fmt.Fprint(conn, "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor=\"0.4.9.11\"\r\n250 OK\r\n")
				} else if cookiePath != "" {
					fmt.Fprintf(conn, "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE COOKIEFILE=\"%s\"\r\n250-VERSION Tor=\"0.4.9.11\"\r\n250 OK\r\n", cookiePath)
				} else {
					fmt.Fprint(conn, "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/unavailable/control_auth_cookie\"\r\n250-VERSION Tor=\"0.4.9.11\"\r\n250 OK\r\n")
				}
			case strings.HasPrefix(line, "AUTHCHALLENGE SAFECOOKIE "):
				clientNonce, decodeErr := hex.DecodeString(strings.TrimPrefix(line, "AUTHCHALLENGE SAFECOOKIE "))
				if decodeErr != nil {
					return
				}
				serverNonce := []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
				serverHash := safeCookieHash(safeCookieServerKey, cookie, clientNonce, serverNonce)
				expectedCookieAuth = "AUTHENTICATE " + hex.EncodeToString(safeCookieHash(safeCookieClientKey, cookie, clientNonce, serverNonce))
				fmt.Fprintf(conn, "250 AUTHCHALLENGE SERVERHASH=%s SERVERNONCE=%s\r\n", hex.EncodeToString(serverHash), hex.EncodeToString(serverNonce))
			case strings.HasPrefix(line, "AUTHENTICATE "):
				expectedAuth := "AUTHENTICATE " + hex.EncodeToString([]byte(password))
				if cookiePath != "" {
					expectedAuth = expectedCookieAuth
				}
				if line != expectedAuth {
					fmt.Fprint(conn, "515 Bad authentication\r\n")
					continue
				}
				fmt.Fprint(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "ADD_ONION "):
				fmt.Fprintf(conn, "250-ServiceID=%s\r\n250 OK\r\n", strings.Repeat("a", 56))
			case strings.HasPrefix(line, "DEL_ONION "):
				fmt.Fprint(conn, "250 OK\r\n")
			case line == "QUIT":
				fmt.Fprint(conn, "250 closing connection\r\n")
				commands <- strings.Join(seen, "\n")
				return
			default:
				fmt.Fprint(conn, "510 Unrecognized command\r\n")
			}
		}
		commands <- strings.Join(seen, "\n")
	}()
	stop := func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fake Tor control server did not stop")
		}
	}
	return listener.Addr().String(), commands, stop
}

func safeCookieHash(key string, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	for _, part := range parts {
		mac.Write(part)
	}
	return mac.Sum(nil)
}
