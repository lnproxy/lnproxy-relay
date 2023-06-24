package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/lnproxy/lnc"
	"github.com/lnproxy/lnproxy"
)

var (
	relayParameters = lnproxy.RelayParameters{
		MinAmountMsat:            100000,
		ExpiryBuffer:             300,
		DefaultFeeBudgetBaseMsat: 1000,
		DefaultFeeBudgetPPM:      9000,
		MinFeeBudgetMsat:         1000,
		RoutingFeeBaseMsat:       100,
		RoutingFeePPM:            1000,
		CltvDeltaAlpha:           3,
		CltvDeltaBeta:            4,
		// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
		MaxCltvDelta: 1800,
		MinCltvDelta: 120,
		// Should be set so that CltvDeltaAlpha blocks are very unlikely to be added before timeout
		PaymentTimeout:        120,
		PaymentTimePreference: 0.9,
	}

	lnd *lnc.Lnd

	validPath = regexp.MustCompile("^/api/(lnbc.*1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)")
)

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	m := validPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}

	x := lnproxy.ProxyParameters{Invoice: m[1]}
	routing_msat_string := r.URL.Query().Get("routing_msat")
	if routing_msat_string != "" {
		routing_msat, err := strconv.ParseUint(routing_msat_string, 10, 64)
		if err != nil {
			http.Error(w, "Invalid custom routing budget", http.StatusBadRequest)
			return
		}
		x.RoutingMsat.Set(routing_msat)
	}

	proxy_invoice, err := lnproxy.Relay(lnd, relayParameters, x)
	if errors.Is(err, lnproxy.ClientFacing) {
		http.Error(w, strings.TrimSpace(err.Error()), http.StatusInternalServerError)
		return
	} else if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", proxy_invoice)
}

func specApiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")

	x := lnproxy.ProxyParameters{}
	err := json.NewDecoder(r.Body).Decode(&x)
	if err != nil {
		log.Println("Error decoding body:", err)
		json.NewEncoder(w).Encode(makeJsonError("Error decoding request"))
		return
	}

	proxy_invoice, err := lnproxy.Relay(lnd, relayParameters, x)
	if errors.Is(err, lnproxy.ClientFacing) {
		json.NewEncoder(w).Encode(makeJsonError(strings.TrimSpace(err.Error())))
		return
	} else if err != nil {
		json.NewEncoder(w).Encode(makeJsonError("Internal relay error"))
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
	httpPort := flag.String("port", "4747", "http port over which to expose api")
	lndHostString := flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
	lndCertPath := flag.String(
		"lnd-cert",
		".lnd/tls.cert",
		"lnd's self-signed cert (set to empty string for no-rest-tls=true)")

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
			uri:/routerrpc.Router/SendPaymentV2
`, os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}

	flag.Parse()
	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	macaroonBytes, err := os.ReadFile(flag.Args()[0])
	if err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "Unable to read lnproxy macaroon file: %v\n", err)
		os.Exit(2)
	}
	macaroon := hex.EncodeToString(macaroonBytes)

	lndHost, err := url.Parse(*lndHostString)
	if err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "Unable to parse lnd host url: %v\n", err)
		os.Exit(2)
	}
	// If this is not set then websocket errors:
	lndHost.Path = "/"

	var lndTlsConfig *tls.Config
	if *lndCertPath == "" {
		lndTlsConfig = &tls.Config{}
	} else {
		lndCert, err := os.ReadFile(*lndCertPath)
		if err != nil {
			fmt.Fprintf(flag.CommandLine.Output(), "Unable to read lnd tls certificate file: %v\n", err)
			os.Exit(2)
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

	lnd = &lnc.Lnd{
		Host:      lndHost,
		Client:    lndClient,
		TlsConfig: lndTlsConfig,
		Macaroon:  macaroon,
	}

	http.HandleFunc("/spec", specApiHandler)
	http.HandleFunc("/api/", apiHandler)

	log.Fatalln(http.ListenAndServe("localhost:"+*httpPort, nil))
}
