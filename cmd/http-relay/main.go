package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/lnproxy/lnc"
	"github.com/lnproxy/lnproxy-relay"
)

var lnproxy_relay *relay.Relay

func specApiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")

	x := relay.ProxyParameters{}
	err := json.NewDecoder(r.Body).Decode(&x)
	if err != nil {
		log.Println("error decoding request:", err)
		body, err := io.ReadAll(r.Body)
		if err != nil && err != io.EOF {
			log.Println("error reading request:", err)
		} else if len(body) > 0 {
			log.Println("request:", string(body))
		}
		json.NewEncoder(w).Encode(makeJsonError("bad request"))
		return
	}

	proxy_invoice, err := lnproxy_relay.OpenCircuit(x)
	if errors.Is(err, relay.ClientFacing) {
		log.Println("client facing error", strings.TrimSpace(err.Error()), "for", x)
		json.NewEncoder(w).Encode(makeJsonError(strings.TrimSpace(err.Error())))
		return
	} else if err != nil {
		log.Println("internal error", strings.TrimSpace(err.Error()), "for", x)
		json.NewEncoder(w).Encode(makeJsonError("internal error"))
		return
	}

	json.NewEncoder(w).Encode(struct {
		WrappedInvoice string `json:"proxy_invoice"`
	}{
		WrappedInvoice: proxy_invoice,
	})
}

type JsonError struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func makeJsonError(reason string) JsonError {
	return JsonError{
		Status: "ERROR",
		Reason: reason,
	}
}

func main() {
	httpHostFlag := flag.String("host", "localhost", "http host over which to expose api")
	httpPortFlag := flag.String("port", "4747", "http port over which to expose api")
	lndHostStringFlag := flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
	lndCertPathFlag := flag.String(
		"lnd-cert",
		".lnd/tls.cert",
		"lnd's self-signed cert (set to empty string for no-rest-tls=true)",
	)

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

	lnproxy_relay = relay.NewRelay(lnd)

	http.HandleFunc("/spec", specApiHandler)

	server := &http.Server{
		Addr:              httpHost + ":" + httpPort,
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
	lnproxy_relay.WaitGroup.Wait()
}
