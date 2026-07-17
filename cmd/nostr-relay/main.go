package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/lnproxy/lnc"
	relay "github.com/lnproxy/lnproxy-relay"
	"github.com/lnproxy/lnproxy-relay/httpapi"
	"github.com/lnproxy/lnproxy-relay/nostr"
)

// defaultNostrRelays is the working default relay set. It is overridable so
// operators are never locked to these.
const defaultNostrRelays = "wss://nos.lol,wss://relay.damus.io,wss://relay.primal.net,wss://nostr.mom"

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// splitCSV splits a comma-separated list, trimming whitespace and dropping
// empty entries.
func splitCSV(s string) []string {
	var out []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func envInt(key string, fallback int) (int, error) {
	value := envOr(key, strconv.Itoa(fallback))
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return parsed, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := envOr(key, fallback.String())
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return parsed, nil
}

func envBool(key string, fallback bool) (bool, error) {
	value := envOr(key, strconv.FormatBool(fallback))
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s: %w", key, err)
	}
	return parsed, nil
}

func main() {
	lndHostStringFlag := flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
	lndCertPathFlag := flag.String("lnd-cert", ".lnd/tls.cert", "lnd's self-signed cert (empty string for no-rest-tls=true)")

	keyPathFlag := flag.String("nostr-key", "lnproxy-nostr.key", "path to persistent nostr secret key (created if absent)")
	relaysFlag := flag.String("nostr-relays", "", "comma-separated nostr relay URLs (default built-in set or LNPROXY_NOSTR_RELAYS)")
	advertisedRelaysFlag := flag.String("advertised-nostr-relays", "", "optional client-reachable aliases for nostr relays (or LNPROXY_ADVERTISED_NOSTR_RELAYS)")
	networkFlag := flag.String("network", "mainnet", "bitcoin network: mainnet|testnet|signet|regtest (or LNPROXY_NETWORK)")
	featuresFlag := flag.String("features", "pay_bolt11,pay_bolt11_blinded,wrap_bolt11", "comma-separated advertised feature flags")
	minRequestPoWFlag := flag.Int("min-request-pow", 20, "minimum NIP-13 difficulty required on wrap requests")
	announcePoWFlag := flag.Int("announce-pow", 20, "NIP-13 difficulty mined into each offer event")
	idPoWFlag := flag.Int("identity-pow", 0, "optional anonymous identity proof of work bits to mine (0 = none)")
	disableLNSigningFlag := flag.Bool("disable-ln-signing", false, "do not attest the nostr identity with the LN node key")
	offerIntervalFlag := flag.Duration("offer-interval", 10*time.Minute, "how often to re-publish the offer")
	urlsFlag := flag.String("urls", "", "comma-separated direct HTTP/onion wrap endpoints to advertise (optional)")
	httpListenFlag := flag.String("http-listen", "", "optional direct HTTP listen address, for example 127.0.0.1:4747 (or LNPROXY_HTTP_LISTEN)")
	httpMaxConcurrentFlag := flag.Int("http-max-concurrent", 8, "maximum concurrent direct HTTP wrap handlers")
	httpRequestIntervalFlag := flag.Duration("http-request-interval", 5*time.Second, "global interval between direct HTTP requests (0 disables)")
	httpRequestBurstFlag := flag.Int("http-request-burst", 3, "initial and maximum direct HTTP request burst")
	torFlag := flag.Bool("tor", false, "use Tor for nostr connections and an ephemeral onion endpoint (or LNPROXY_TOR)")
	torProxyFlag := flag.Bool("tor-proxy", true, "proxy nostr relay connections through Tor when Tor is enabled")
	torHiddenServiceFlag := flag.Bool("tor-hidden-service", true, "create and advertise an ephemeral v3 onion service when Tor is enabled")
	torSOCKSFlag := flag.String("tor-socks", "127.0.0.1:9050", "Tor SOCKS5 address")
	torSOCKSUsernameFlag := flag.String("tor-socks-username", "", "optional Tor SOCKS username for stream isolation")
	torSOCKSPasswordFlag := flag.String("tor-socks-password", "", "optional Tor SOCKS password for stream isolation")
	torControlFlag := flag.String("tor-control", "127.0.0.1:9051", "Tor control address")
	torControlPasswordFlag := flag.String("tor-control-password", "", "optional Tor control password (empty uses SAFECOOKIE)")
	torControlCookieFlag := flag.String("tor-control-cookie", "", "local path to Tor SAFECOOKIE file (default path reported by Tor)")
	torTargetFlag := flag.String("tor-target", "", "hidden-service target (default derived from -http-listen)")
	torVirtualPortFlag := flag.Int("tor-virtual-port", 80, "port exposed by the ephemeral onion service")

	minMsatFlag := flag.Uint64("min-msat", 0, "minimum invoice amount in msat (0 = default/env)")
	maxMsatFlag := flag.Uint64("max-msat", 0, "maximum invoice amount in msat (0 = default/env)")
	baseFeeMsatFlag := flag.Uint64("base-fee-msat", 0, "relay base fee in msat (0 = default/env)")
	feePpmFlag := flag.Uint64("fee-ppm", 0, "relay proportional fee in ppm (0 = default/env)")
	maxExpiryFlag := flag.Uint64("max-expiry", 0, "maximum proxy invoice expiry in seconds (0 = default/env)")
	maxActiveCircuitsFlag := flag.Uint64("max-active-circuits", 0, "maximum active hold-invoice circuits (0 = default/env)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `usage: %s [flags] lnproxy.macaroon
  lnproxy.macaroon
	Path to lnproxy macaroon. Generate it with:
		lncli bakemacaroon --save_to lnproxy.macaroon \
			uri:/lnrpc.Lightning/DecodePayReq \
			uri:/lnrpc.Lightning/LookupInvoice \
			uri:/lnrpc.Lightning/SignMessage \
			uri:/lnrpc.Lightning/GetInfo \
			uri:/invoicesrpc.Invoices/AddHoldInvoice \
			uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
			uri:/invoicesrpc.Invoices/CancelInvoice \
			uri:/invoicesrpc.Invoices/SettleInvoice \
			uri:/routerrpc.Router/SendPaymentV2 \
			uri:/routerrpc.Router/EstimateRouteFee \
			uri:/chainrpc.ChainKit/GetBestBlock
	Omit SignMessage/GetInfo if running with -disable-ln-signing.
`, os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	lndHostString := envOr("LNPROXY_LND_HOST", *lndHostStringFlag)
	lndCertPath := envOr("LNPROXY_LND_CERT", *lndCertPathFlag)
	relaysCSV := *relaysFlag
	if relaysCSV == "" {
		relaysCSV = envOr("LNPROXY_NOSTR_RELAYS", defaultNostrRelays)
	}
	relays := splitCSV(relaysCSV)
	if len(relays) == 0 {
		log.Fatalln("no nostr relays configured")
	}
	advertisedRelaysCSV := *advertisedRelaysFlag
	if advertisedRelaysCSV == "" {
		advertisedRelaysCSV = os.Getenv("LNPROXY_ADVERTISED_NOSTR_RELAYS")
	}
	advertisedRelays := splitCSV(advertisedRelaysCSV)
	if len(advertisedRelays) == 0 {
		advertisedRelays = relays
	}
	httpMaxConcurrent, err := envInt("LNPROXY_HTTP_MAX_CONCURRENT", *httpMaxConcurrentFlag)
	if err != nil {
		log.Fatalln("invalid direct HTTP concurrency:", err)
	}
	if httpMaxConcurrent <= 0 {
		log.Fatalln("direct HTTP concurrency must be greater than zero")
	}
	httpRequestInterval, err := envDuration("LNPROXY_HTTP_REQUEST_INTERVAL", *httpRequestIntervalFlag)
	if err != nil {
		log.Fatalln("invalid direct HTTP request interval:", err)
	}
	if httpRequestInterval < 0 {
		log.Fatalln("direct HTTP request interval must not be negative")
	}
	httpRequestBurst, err := envInt("LNPROXY_HTTP_REQUEST_BURST", *httpRequestBurstFlag)
	if err != nil {
		log.Fatalln("invalid direct HTTP request burst:", err)
	}
	if httpRequestBurst <= 0 {
		log.Fatalln("direct HTTP request burst must be greater than zero")
	}
	torEnabled, err := envBool("LNPROXY_TOR", *torFlag)
	if err != nil {
		log.Fatalln("invalid Tor configuration:", err)
	}
	torProxy, err := envBool("LNPROXY_TOR_PROXY", *torProxyFlag)
	if err != nil {
		log.Fatalln("invalid Tor configuration:", err)
	}
	torHiddenService, err := envBool("LNPROXY_TOR_HIDDEN_SERVICE", *torHiddenServiceFlag)
	if err != nil {
		log.Fatalln("invalid Tor configuration:", err)
	}
	torVirtualPort, err := envInt("LNPROXY_TOR_VIRTUAL_PORT", *torVirtualPortFlag)
	if err != nil {
		log.Fatalln("invalid Tor configuration:", err)
	}

	network, err := nostr.ParseNetwork(envOr("LNPROXY_NETWORK", *networkFlag))
	if err != nil {
		log.Fatalln("invalid network configuration:", err)
	}

	lnproxyMacaroon := os.Getenv("LNPROXY_MACAROON")
	if lnproxyMacaroon == "" && len(flag.Args()) == 1 {
		lnproxyMacaroon = flag.Args()[0]
	} else if lnproxyMacaroon == "" {
		flag.Usage()
	}

	macaroonBytes, err := os.ReadFile(lnproxyMacaroon)
	if err != nil {
		log.Fatalln("unable to read lnproxy macaroon file:", err)
	}
	macaroon := hex.EncodeToString(macaroonBytes)

	lndHost, err := url.Parse(lndHostString)
	if err != nil {
		log.Fatalln("unable to parse lnd host url:", err)
	}
	lndHost.Path = "/"

	var lndTlsConfig *tls.Config
	if lndCertPath == "" {
		lndTlsConfig = &tls.Config{}
	} else {
		lndCert, err := os.ReadFile(lndCertPath)
		if err != nil {
			log.Fatalln("unable to read lnd tls certificate file:", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(lndCert)
		lndTlsConfig = &tls.Config{RootCAs: caCertPool}
	}

	lndClient := &http.Client{Transport: &http.Transport{TLSClientConfig: lndTlsConfig}}
	lnd := &lnc.Lnd{Host: lndHost, Client: lndClient, TlsConfig: lndTlsConfig, Macaroon: macaroon}

	lnproxyRelay := relay.NewRelay(lnd)
	if err := lnproxyRelay.RelayParameters.ApplyEnvOverrides(); err != nil {
		log.Fatalln("invalid environment configuration:", err)
	}
	if *minMsatFlag != 0 {
		lnproxyRelay.MinAmountMsat = *minMsatFlag
	}
	if *maxMsatFlag != 0 {
		lnproxyRelay.MaxAmountMsat = *maxMsatFlag
	}
	if *baseFeeMsatFlag != 0 {
		lnproxyRelay.RoutingFeeBaseMsat = *baseFeeMsatFlag
	}
	if *feePpmFlag != 0 {
		lnproxyRelay.RoutingFeePPM = *feePpmFlag
	}
	if *maxExpiryFlag != 0 {
		lnproxyRelay.MaxExpiry = *maxExpiryFlag
	}
	if *maxActiveCircuitsFlag != 0 {
		lnproxyRelay.MaxActiveCircuits = *maxActiveCircuitsFlag
	}
	if err := lnproxyRelay.RelayParameters.Validate(); err != nil {
		log.Fatalln("invalid relay configuration:", err)
	}

	identity, err := nostr.LoadOrCreateIdentity(*keyPathFlag)
	if err != nil {
		log.Fatalln("nostr identity error:", err)
	}
	log.Println("nostr public key:", identity.PublicKey)

	httpListen := envOr("LNPROXY_HTTP_LISTEN", *httpListenFlag)
	torTarget := envOr("LNPROXY_TOR_TARGET", *torTargetFlag)
	if torEnabled && torHiddenService && torTarget == "" && httpListen != "" {
		torTarget, err = defaultTorTarget(httpListen)
		if err != nil {
			log.Fatalln("invalid Tor configuration:", err)
		}
	}
	torCfg := torConfig{
		Enabled:         torEnabled,
		ProxyNostr:      torProxy,
		HiddenService:   torHiddenService,
		SOCKSAddress:    envOr("LNPROXY_TOR_SOCKS", *torSOCKSFlag),
		SOCKSUsername:   envOr("LNPROXY_TOR_SOCKS_USERNAME", *torSOCKSUsernameFlag),
		SOCKSPassword:   envOr("LNPROXY_TOR_SOCKS_PASSWORD", *torSOCKSPasswordFlag),
		ControlAddress:  envOr("LNPROXY_TOR_CONTROL", *torControlFlag),
		ControlPassword: envOr("LNPROXY_TOR_CONTROL_PASSWORD", *torControlPasswordFlag),
		ControlCookie:   envOr("LNPROXY_TOR_CONTROL_COOKIE", *torControlCookieFlag),
		TargetAddress:   torTarget,
		VirtualPort:     torVirtualPort,
	}
	if err := torCfg.validate(httpListen); err != nil {
		log.Fatalln("invalid Tor configuration:", err)
	}
	logTorStartup(log.Default(), torCfg)
	if torCfg.Enabled && torCfg.ProxyNostr {
		torClient, err := newTorHTTPClient(torCfg.SOCKSAddress, torCfg.SOCKSUsername, torCfg.SOCKSPassword)
		if err != nil {
			log.Fatalln("invalid Tor proxy configuration:", err)
		}
		// go-nostr uses http.DefaultClient for WebSocket handshakes. This
		// dedicated transport has no direct-network fallback.
		http.DefaultClient = torClient
	}
	urlsCSV := *urlsFlag
	if urlsCSV == "" {
		urlsCSV = os.Getenv("LNPROXY_URLS")
	}
	urls := splitCSV(urlsCSV)
	var onionService *ephemeralOnion
	if torCfg.Enabled && torCfg.HiddenService {
		onionService, err = createEphemeralOnion(ctx, torCfg)
		if err != nil {
			log.Fatalln("Tor hidden-service setup failed:", err)
		}
		urls = appendUnique(urls, onionService.URL())
	}
	features := splitCSV(*featuresFlag)
	if httpListen != "" && len(urls) > 0 {
		features = appendUnique(features, nostr.FeatureRequestIDV1)
	}

	offer := nostr.Offer{
		BaseFeeMsat:      lnproxyRelay.RoutingFeeBaseMsat,
		FeePPM:           lnproxyRelay.RoutingFeePPM,
		MinAmountMsat:    lnproxyRelay.MinAmountMsat,
		MaxAmountMsat:    lnproxyRelay.MaxAmountMsat,
		MaxExpirySeconds: lnproxyRelay.MaxExpiry,
		MinRequestPoW:    *minRequestPoWFlag,
		Features:         features,
		URLs:             urls,
	}
	onionURL := ""
	if onionService != nil {
		onionURL = onionService.URL()
	}
	logAdvertisedURLs(log.Default(), onionURL, offer.URLs)

	// Optional LN node attestation binds this nostr identity to the node.
	if !*disableLNSigningFlag {
		if err := attest(newLNDSigner(lnd), identity, &offer); err != nil {
			log.Fatalln("node attestation failed (use -disable-ln-signing to skip):", err)
		}
		log.Println("attested nostr identity with node", offer.NodePubkey)
	} else if *idPoWFlag > 0 {
		nonce, bitsGot, err := nostr.MineAnnouncePoW(identity.PublicKey, *idPoWFlag, 1, 0)
		if err != nil {
			log.Fatalln("identity proof of work failed:", err)
		}
		offer.PoWNonce = fmt.Sprintf("0x%x", nonce)
		log.Printf("mined anonymous identity proof of work: %d bits", bitsGot)
	}

	cfg := nostr.Config{
		SecretKey:         identity.SecretKey,
		PublicKey:         identity.PublicKey,
		Relays:            relays,
		AdvertisedRelays:  advertisedRelays,
		Network:           network,
		Offer:             offer,
		AnnouncePoWTarget: *announcePoWFlag,
		OfferInterval:     *offerIntervalFlag,
	}

	pool := gonostr.NewSimplePool(ctx)
	server := nostr.NewServer(lnproxyRelay, offer, identity.PublicKey)
	transport := nostr.NewTransport(cfg, pool, server)
	var directServer *http.Server
	if httpListen != "" {
		directServer = &http.Server{
			Addr: httpListen,
			Handler: httpapi.NewHandlerWithOptions(server, httpapi.Options{
				RequireRequestID:   offer.HasFeature(nostr.FeatureRequestIDV1),
				ProviderPubkey:     identity.PublicKey,
				MaxConcurrent:      httpMaxConcurrent,
				MinRequestInterval: httpRequestInterval,
				RequestBurst:       httpRequestBurst,
			}),
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
	}

	log.Printf("relay limits: min=%d msat max=%d msat fee=%d msat + %d ppm",
		lnproxyRelay.MinAmountMsat, lnproxyRelay.MaxAmountMsat,
		lnproxyRelay.RoutingFeeBaseMsat, lnproxyRelay.RoutingFeePPM)
	log.Printf("advertising %s features %v on relays %v", network, offer.Features, advertisedRelays)
	if directServer != nil {
		log.Printf("direct HTTP endpoint listening on %s; advertised URLs %v", directServer.Addr, offer.URLs)
		log.Printf("direct HTTP limits: concurrent=%d interval=%s burst=%d",
			httpMaxConcurrent, httpRequestInterval, httpRequestBurst)
		if len(offer.URLs) == 0 {
			log.Println("direct HTTP endpoint is not advertised because -urls is empty")
		}
	}

	errCh := make(chan error, 3)
	transportDone := make(chan struct{})
	go func() {
		defer close(transportDone)
		for ctx.Err() == nil {
			if err := transport.Run(ctx); err != nil && ctx.Err() == nil {
				log.Println("nostr transport stopped, retrying in 5s:", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()

	var directDone chan struct{}
	if directServer != nil {
		directDone = make(chan struct{})
		go func() {
			defer close(directDone)
			if err := directServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("direct HTTP server: %w", err)
			}
		}()
	}
	var onionDone chan struct{}
	if onionService != nil {
		onionDone = make(chan struct{})
		go func() {
			defer close(onionDone)
			if err := onionService.Watch(ctx); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		log.Println(err)
	}
	stopSignals()
	log.Println("shutting down transports...")
	if directServer != nil {
		if err := directServer.Shutdown(context.Background()); err != nil {
			log.Println("direct HTTP shutdown error:", err)
		}
		<-directDone
	}
	<-transportDone
	if onionService != nil {
		<-onionDone
		if err := onionService.Close(); err != nil {
			log.Println("Tor hidden-service shutdown error:", err)
		}
	}
	log.Println("waiting for open circuits...")
	lnproxyRelay.WaitGroup.Wait()
	log.Println("shutdown complete")
}

// attest signs the attestation message with the node key and fills the offer.
func attest(signer nodeSigner, identity nostr.Identity, offer *nostr.Offer) error {
	pubkey, err := signer.IdentityPubkey()
	if err != nil {
		return err
	}
	sig, err := signer.SignMessage(nostr.AttestationMessage(identity.PublicKey))
	if err != nil {
		return err
	}
	offer.NodePubkey = pubkey
	offer.NodeSig = sig
	return nil
}
