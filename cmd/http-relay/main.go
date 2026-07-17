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
	"time"

	"github.com/lnproxy/lnc"
	"github.com/lnproxy/lnproxy-relay"
	"github.com/lnproxy/lnproxy-relay/httpapi"
	"github.com/lnproxy/lnproxy-relay/nostr"
)

func main() {
	httpHostFlag := flag.String("host", "localhost", "http host over which to expose api")
	httpPortFlag := flag.String("port", "4747", "http port over which to expose api")
	lndHostStringFlag := flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
	lndCertPathFlag := flag.String(
		"lnd-cert",
		".lnd/tls.cert",
		"lnd's self-signed cert (set to empty string for no-rest-tls=true)",
	)
	minMsatFlag := flag.Uint64("min-msat", 0, "minimum invoice amount in msat (0 = keep default/env)")
	maxMsatFlag := flag.Uint64("max-msat", 0, "maximum invoice amount in msat (0 = keep default/env)")
	baseFeeMsatFlag := flag.Uint64("base-fee-msat", 0, "relay base fee in msat (0 = keep default/env)")
	feePpmFlag := flag.Uint64("fee-ppm", 0, "relay proportional fee in ppm (0 = keep default/env)")
	maxExpiryFlag := flag.Uint64("max-expiry", 0, "maximum proxy invoice expiry in seconds (0 = keep default/env)")
	maxActiveCircuitsFlag := flag.Uint64("max-active-circuits", 0, "maximum active hold-invoice circuits (0 = keep default/env)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `usage: %s [flags] lnproxy.macaroon
  lnproxy.macaroon
	Path to lnproxy macaroon. Generate it with:
		lncli bakemacaroon --save_to lnproxy.macaroon \
			uri:/lnrpc.Lightning/DecodePayReq \
			uri:/lnrpc.Lightning/LookupInvoice \
			uri:/invoicesrpc.Invoices/AddHoldInvoice \
			uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
			uri:/invoicesrpc.Invoices/CancelInvoice \
			uri:/invoicesrpc.Invoices/SettleInvoice \
			uri:/routerrpc.Router/SendPaymentV2 \
			uri:/routerrpc.Router/EstimateRouteFee \
			uri:/chainrpc.ChainKit/GetBestBlock
`, os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}

	flag.Parse()

	httpHost := os.Getenv("LNPROXY_HOST")
	if httpHost == "" {
		httpHost = *httpHostFlag
	}
	httpPort := os.Getenv("LNPROXY_PORT")
	if httpPort == "" {
		httpPort = *httpPortFlag
	}
	lndHostString := os.Getenv("LNPROXY_LND_HOST")
	if lndHostString == "" {
		lndHostString = *lndHostStringFlag
	}
	lndCertPath := os.Getenv("LNPROXY_LND_CERT")
	if lndCertPath == "" {
		lndCertPath = *lndCertPathFlag
	}

	lnproxyMacaroon := os.Getenv("LNPROXY_MACAROON")
	if lnproxyMacaroon == "" && len(flag.Args()) == 1 {
		lnproxyMacaroon = flag.Args()[0]
	} else if lnproxyMacaroon == "" {
		flag.Usage()
		os.Exit(2)
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
	// If this is not set then websocket errors:
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

	lndClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: lndTlsConfig,
		},
	}

	lnd := &lnc.Lnd{
		Host:      lndHost,
		Client:    lndClient,
		TlsConfig: lndTlsConfig,
		Macaroon:  macaroon,
	}

	lnproxyRelay := relay.NewRelay(lnd)

	// Operators set their own fees and limits. Precedence: flag (if non-zero)
	// overrides env, env overrides the built-in default.
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
	log.Printf("relay limits: min=%d msat max=%d msat fee=%d msat + %d ppm max_expiry=%d s",
		lnproxyRelay.MinAmountMsat, lnproxyRelay.MaxAmountMsat,
		lnproxyRelay.RoutingFeeBaseMsat, lnproxyRelay.RoutingFeePPM, lnproxyRelay.MaxExpiry)

	wrapper := nostr.NewServer(lnproxyRelay, nostr.Offer{
		Features:         []string{nostr.FeatureWrapBolt11},
		MaxExpirySeconds: lnproxyRelay.MaxExpiry,
	})

	server := &http.Server{
		Addr:              httpHost + ":" + httpPort,
		Handler:           httpapi.NewHandler(wrapper),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		if err := server.Shutdown(context.Background()); err != nil {
			log.Println("HTTP server shutdown error:", err)
		}
		close(idleConnsClosed)
		log.Println("HTTP server shutdown")
	}()
	go func() {
		log.Println("HTTP server listening on:", server.Addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Println("HTTP server ListenAndServe error:", err)
		}
	}()
	<-idleConnsClosed

	signal.Reset(os.Interrupt)
	log.Println("waiting for open circuits...")
	lnproxyRelay.WaitGroup.Wait()
}
