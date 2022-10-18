package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	"regexp"
	"time"

	"golang.org/x/net/websocket"
)

const (
	EXPIRY_BUFFER    = 600
	FEE_BASE_MSAT    = 1000
	FEE_PPM          = 6000
	CLTV_DELTA_ALPHA = 3
	CLTV_DELTA_BETA  = 6
	// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
	MAX_CLTV_DELTA = 2016
)

var (
	httpPort      = flag.String("port", "4747", "http port over which to expose api")
	lndHostString = flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
	lndHost       *url.URL
	lndCertPath   = flag.String("lnd-cert", ".lnd/tls.cert", "host for lnd's REST api")
	lndTlsConfig  *tls.Config
	lndClient     *http.Client

	macaroon string
)

type PaymentRequest struct {
	PaymentHash     string `json:"payment_hash"`
	Timestamp       int64  `json:"timestamp,string"`
	Expiry          int64  `json:"expiry,string"`
	Description     string `json:"description"`
	DescriptionHash string `json:"description_hash"`
	NumMsat         int64  `json:"num_msat,string"`
	CltvExpiry      int64  `json:"cltv_expiry,string"`
	Features        map[string]struct {
		Name       string `json:"name"`
		IsRequired bool   `json:"is_required"`
		IsKnown    bool   `json:"is_known"`
	} `json:"features"`
}

func decodePaymentRequest(invoice string) (*PaymentRequest, error) {
	req, err := http.NewRequest(
		"GET",
		lndHost.JoinPath("v1/payreq", invoice).String(),
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)

	resp, err := lndClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		return nil, fmt.Errorf("Unknown v1/payreq error: %#v", x)
	}

	dec := json.NewDecoder(resp.Body)
	p := PaymentRequest{}
	err = dec.Decode(&p)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &p, nil
}

type WrappedPaymentRequest struct {
	Memo            string `json:"memo,omitempty"`
	Hash            []byte `json:"hash"`
	ValueMsat       int64  `json:"value_msat,string"`
	DescriptionHash []byte `json:"description_hash,omitempty"`
	Expiry          int64  `json:"expiry,string"`
	CltvExpiry      int64  `json:"cltv_expiry,string"`
}

func wrapPaymentRequest(p *PaymentRequest) (*WrappedPaymentRequest, error) {
	for flag, feature := range p.Features {
		switch flag {
		case "8", "9", "14", "15", "16", "17":
		default:
			log.Printf("unhandled feature flag: %s\n\t%v\n", flag, feature)
			if feature.IsRequired {
				return nil, fmt.Errorf("Cannot wrap %s invoices", feature.Name)
			}
		}
	}
	q := WrappedPaymentRequest{}
	if p.DescriptionHash != "" {
		description_hash, err := hex.DecodeString(p.DescriptionHash)
		if err != nil {
			return nil, err
		}
		q.DescriptionHash = description_hash
	} else {
		q.Memo = p.Description
	}
	hash, err := hex.DecodeString(p.PaymentHash)
	if err != nil {
		return nil, err
	}
	q.Hash = hash
	if p.NumMsat == 0 {
		q.ValueMsat = 0
	} else {
		q.ValueMsat = p.NumMsat + (p.NumMsat*FEE_PPM)/1_000_000 + FEE_BASE_MSAT
	}
	q.Expiry = p.Timestamp + p.Expiry - time.Now().Unix() - EXPIRY_BUFFER
	if q.Expiry < 0 {
		err = fmt.Errorf("Payment request expiration is too close.")
		return nil, err
	}
	q.CltvExpiry = p.CltvExpiry*CLTV_DELTA_BETA + CLTV_DELTA_ALPHA
	if q.CltvExpiry >= MAX_CLTV_DELTA {
		return nil, fmt.Errorf("cltv_expiry is too long")
	}
	return &q, nil
}

var ErrInvoiceExists = errors.New("Invoice with payment hash already exists")

func addWrappedInvoice(p *WrappedPaymentRequest) (string, error) {
	params, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(params)
	req, err := http.NewRequest(
		"POST",
		lndHost.JoinPath("v2/invoices/hodl").String(),
		buf,
	)
	if err != nil {
		return "", err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := lndClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		if x, ok := x.(map[string]interface{}); ok {
			if x["message"] == "invoice with payment hash already exists" {
				return "", ErrInvoiceExists
			}
		}
		return "", fmt.Errorf("Unknown v2/invoices/hodl error: %#v", x)
	}
	dec := json.NewDecoder(resp.Body)
	pr := struct {
		PaymentRequest string `json:"payment_request"`
	}{}
	err = dec.Decode(&pr)
	if err != nil && err != io.EOF {
		return "", err
	}

	return pr.PaymentRequest, nil
}

func lookupInvoice(hash []byte) (string, error) {
	req, err := http.NewRequest(
		"GET",
		lndHost.JoinPath("v1/invoice", hex.EncodeToString(hash)).String(),
		nil,
	)
	if err != nil {
		return "", err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)

	resp, err := lndClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		return "", fmt.Errorf("Unknown v1/invoice error: %#v", x)
	}

	dec := json.NewDecoder(resp.Body)
	s := struct {
		PaymentRequest string `json:"payment_request"`
	}{}
	err = dec.Decode(&s)
	if err != nil && err != io.EOF {
		return "", err
	}

	return s.PaymentRequest, nil
}

func watchWrappedInvoice(p *WrappedPaymentRequest, original_invoice string) {
	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", macaroon)
	loc := *lndHost
	loc.Scheme = "wss"
	origin := *lndHost
	origin.Scheme = "http"

	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc.JoinPath("v2/invoices/subscribe", base64.URLEncoding.EncodeToString(p.Hash)),
		Origin:    &origin,
		TlsConfig: lndTlsConfig,
		Header:    header,
		Version:   13,
	})
	if err != nil {
		log.Panicln(err)
	}
	err = websocket.JSON.Send(ws, struct{}{})
	if err != nil {
		log.Panicln(err)
	}
	for {
		message := struct {
			Result struct {
				State       string `json:"state"`
				AmtPaidMsat int64  `json:"amt_paid_msat,string"`
			} `json:"result"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			log.Panicln(err)
		}

		switch message.Result.State {
		case "OPEN":
			continue
		case "ACCEPTED":
			settleWrappedInvoice(p, message.Result.AmtPaidMsat, original_invoice)
			return
		case "SETTLED", "CANCELED":
			return
		default:
			log.Panicln("Unknown invoice status")
		}

		if err == io.EOF {
			log.Panicln("Unexpected EOF while watching invoice")
		}
	}
}

func cancelWrappedInvoice(hash []byte) {
	params, err := json.Marshal(
		struct {
			PaymentHash []byte `json:"payment_hash"`
		}{
			PaymentHash: hash,
		},
	)
	if err != nil {
		log.Panicln(err)
	}
	buf := bytes.NewBuffer(params)
	req, err := http.NewRequest(
		"POST",
		lndHost.JoinPath("v2/invoices/cancel").String(),
		buf,
	)
	if err != nil {
		log.Panicln(err)
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := lndClient.Do(req)
	if err != nil {
		log.Panicln(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		log.Panicln(fmt.Errorf("Unknown v2/invoices/cancel error: %#v", x))
	}
	dec := json.NewDecoder(resp.Body)
	var x interface{}
	if err := dec.Decode(&x); err != nil && err != io.EOF {
		log.Panicln(err)
	}
	if x, ok := x.(map[string]interface{}); ok {
		if len(x) != 0 {
			log.Panicln(err)
		}
	} else {
		log.Panicln(fmt.Errorf("Unknown v2/invoices/cancel response: %#v", x))
	}
}

func settleWrappedInvoice(p *WrappedPaymentRequest, paid_msat int64, original_invoice string) {
	var amt_msat int64
	if p.ValueMsat == 0 {
		amt_msat = paid_msat - (paid_msat*FEE_PPM)/1_000_000
	}
	params := struct {
		Invoice           string  `json:"payment_request"`
		AmtMsat           int64   `json:"amt_msat,omitempty,string"`
		TimeoutSeconds    int64   `json:"timeout_seconds"`
		FeeLimitMsat      int64   `json:"fee_limit_msat,string"`
		NoInflightUpdates bool    `json:"no_inflight_updates"`
		CltvLimit         int32   `json:"cltv_limit"`
		Amp               bool    `json:"amp"`
		TimePref          float64 `json:"time_pref"`
	}{
		Invoice:           original_invoice,
		AmtMsat:           amt_msat,
		TimeoutSeconds:    p.Expiry - time.Now().Unix(),
		FeeLimitMsat:      (paid_msat * FEE_PPM) / 1_000_000,
		NoInflightUpdates: true,
		CltvLimit:         int32(p.CltvExpiry - CLTV_DELTA_ALPHA),
		Amp:               false,
		TimePref:          0.9,
	}

	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", macaroon)
	loc := *lndHost
	loc.Scheme = "wss"
	q := url.Values{}
	q.Set("method", "POST")
	loc.RawQuery = q.Encode()
	origin := *lndHost
	origin.Scheme = "http"

	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc.JoinPath("v2/router/send"),
		Origin:    &origin,
		TlsConfig: lndTlsConfig,
		Header:    header,
		Version:   13,
	})
	if err != nil {
		log.Panicln(err)
	}

	err = websocket.JSON.Send(ws, params)
	if err != nil {
		log.Panicln(err)
	}

	var preimage string
InFlight:
	for {
		message := struct {
			Result struct {
				Status   string `json:"status"`
				PreImage string `json:"payment_preimage"`
			} `json:"result"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			log.Panicln(err)
		}
		switch message.Result.Status {
		case "FAILED":
			cancelWrappedInvoice(p.Hash)
			return
		case "UNKNOWN", "IN_FLIGHT":
			time.Sleep(500 * time.Millisecond)
		case "SUCCEEDED":
			preimage = message.Result.PreImage
			log.Printf("preimage (%d): %s\n", paid_msat/1000, preimage)
			break InFlight
		default:
			log.Panicln("Unknown payment status:", message.Result.Status)
		}

		if err == io.EOF {
			log.Panicln("Unexpected EOF while watching invoice")
		}
	}

	preimage2, err := hex.DecodeString(preimage)
	if err != nil {
		log.Panicln(err)
	}
	params2, err := json.Marshal(struct {
		PreImage []byte `json:"preimage"`
	}{
		PreImage: preimage2,
	})
	if err != nil {
		log.Panicln(err)
	}
	buf := bytes.NewBuffer(params2)
	req, err := http.NewRequest(
		"POST",
		lndHost.JoinPath("v2/invoices/settle").String(),
		buf,
	)
	if err != nil {
		log.Panicln(err)
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := lndClient.Do(req)
	if err != nil {
		log.Panicln(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		log.Panicln(fmt.Errorf("Unknown v2/invoices/settle error: %#v", x))
	}
	dec := json.NewDecoder(resp.Body)

	var x interface{}
	dec = json.NewDecoder(resp.Body)
	dec.Decode(&x)
	if x, ok := x.(map[string]interface{}); ok {
		if len(x) != 0 {
			log.Panicln(fmt.Errorf("Unknown v2/invoices/settle response: %#v", x))
		}
	} else {
		log.Panicln(fmt.Errorf("Unknown v2/invoices/settle response: %#v", x))
	}
}

func wrap(invoice string) (string, error) {
	p, err := decodePaymentRequest(invoice)
	if err != nil {
		return "", err
	}
	q, err := wrapPaymentRequest(p)
	if err != nil {
		return "", err
	}
	i, err := addWrappedInvoice(q)
	if err == ErrInvoiceExists {
		i, err = lookupInvoice(q.Hash)
		if err != nil {
			return "", err
		}
		return i, nil
	} else if err != nil {
		return "", err
	}
	go watchWrappedInvoice(q, invoice)
	return i, nil
}

var validPath = regexp.MustCompile("^/(lnbc[a-z0-9]+)$")

func apiHandler(w http.ResponseWriter, r *http.Request) {
	m := validPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	i, err := wrap(m[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", i)
}

func main() {
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
	macaroon = hex.EncodeToString(macaroonBytes)

	lndHost, err = url.Parse(*lndHostString)
	if err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "Unable to parse lnd host url: %v\n", err)
		os.Exit(2)
	}
	// If this is not set then websocket errors:
	lndHost.Path = "/"

	lndCert, err := os.ReadFile(*lndCertPath)
	if err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "Unable to read lnd tls certificate file: %v\n", err)
		os.Exit(2)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(lndCert)
	lndTlsConfig = &tls.Config{RootCAs: caCertPool}
	lndClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: lndTlsConfig,
		},
	}

	http.HandleFunc("/", apiHandler)

	log.Panicln(http.ListenAndServe("localhost:"+*httpPort, nil))
}
