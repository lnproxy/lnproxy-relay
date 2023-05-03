package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/net/websocket"
)

const (
	EXPIRY_BUFFER       = 300
	FEE_BASE_MSAT       = 1000
	FEE_PPM             = 9000
	MIN_CUSTOM_FEE_MSAT = 1000
	MIN_AMOUNT_MSAT     = 100000
	CLTV_DELTA_ALPHA    = 3
	CLTV_DELTA_BETA     = 6
	// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
	MAX_CLTV_DELTA = 2016
)

var (
	httpPort      = flag.String("port", "4747", "http port over which to expose api")
	lndHostString = flag.String("lnd", "https://127.0.0.1:8080", "host for lnd's REST api")
	lndHost       *url.URL
	lndCertPath   = flag.String(
		"lnd-cert",
		".lnd/tls.cert",
		"lnd's self-signed cert (set to empty string for no-rest-tls=true)")
	lndTlsConfig *tls.Config
	lndClient    *http.Client

	macaroon string
)

type PaymentRequest struct {
	PaymentHash     string `json:"payment_hash"`
	Timestamp       int64  `json:"timestamp,string"`
	Expiry          int64  `json:"expiry,string"`
	Description     string `json:"description"`
	DescriptionHash string `json:"description_hash"`
	NumMsat         uint64 `json:"num_msat,string"`
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
	ValueMsat       uint64 `json:"value_msat,string"`
	DescriptionHash []byte `json:"description_hash,omitempty"`
	Expiry          int64  `json:"expiry,string"`
	CltvExpiry      int64  `json:"cltv_expiry,string"`
}

func wrapPaymentRequest(p *PaymentRequest, max_fee_msat uint64) (*WrappedPaymentRequest, error) {
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
		if max_fee_msat == 0 {
			q.ValueMsat = p.NumMsat + (p.NumMsat*FEE_PPM)/1_000_000 + FEE_BASE_MSAT
		} else {
			q.ValueMsat = p.NumMsat + max_fee_msat
		}
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
				return "", fmt.Errorf("Wrapped invoice with that payment hash already exists")
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

func watchWrappedInvoice(p *WrappedPaymentRequest, original_invoice string, max_fee_msat uint64) {
	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", macaroon)
	loc := *lndHost
	if loc.Scheme == "https" {
		loc.Scheme = "wss"
	} else {
		loc.Scheme = "ws"
	}
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
		log.Println("Error while subscribing to invoice:", p, err)
		return
	}
	err = websocket.JSON.Send(ws, struct{}{})
	if err != nil {
		log.Println("Error while subscribing to invoice:", p, err)
		return
	}
	for {
		message := struct {
			Result struct {
				State       string `json:"state"`
				AmtPaidMsat uint64 `json:"amt_paid_msat,string"`
			} `json:"result"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			log.Println("Error while reading from invoice status lnd socket:", p, err)
			return
		}

		switch message.Result.State {
		case "OPEN":
			continue
		case "ACCEPTED":
			settleWrappedInvoice(p, message.Result.AmtPaidMsat, original_invoice, max_fee_msat)
			return
		case "SETTLED", "CANCELED":
			log.Printf("Invoice %s before payment.\n", message.Result.State)
			return
		default:
			log.Printf("Unknown invoice status: %s\n", message.Result.State)
			return
		}

		if err == io.EOF {
			log.Println("Unexpected EOF while watching invoice:", p)
			return
		}
	}
}

func cancelWrappedInvoice(hash []byte) {
	params, _ := json.Marshal(
		struct {
			PaymentHash []byte `json:"payment_hash"`
		}{
			PaymentHash: hash,
		},
	)
	buf := bytes.NewBuffer(params)
	req, err := http.NewRequest(
		"POST",
		lndHost.JoinPath("v2/invoices/cancel").String(),
		buf,
	)
	if err != nil {
		log.Println("Error while canceling invoice:", hash, err)
		return
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := lndClient.Do(req)
	if err != nil {
		log.Println("Error while canceling invoice:", hash, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		log.Println("Unknown v2/invoices/cancel error:", x)
		return
	}
	dec := json.NewDecoder(resp.Body)
	var x interface{}
	if err := dec.Decode(&x); err != nil && err != io.EOF {
		log.Println("Unknown v2/invoices/cancel error:", err)
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		log.Println("Unknown v2/invoices/cancel response:", x)
	}
}

func settleWrappedInvoice(p *WrappedPaymentRequest, paid_msat uint64, original_invoice string, max_fee_msat uint64) {
	var amt_msat uint64
	if max_fee_msat == 0 {
		max_fee_msat = (paid_msat * FEE_PPM) / 1_000_000
	}
	if p.ValueMsat == 0 {
		amt_msat = paid_msat - max_fee_msat
		if amt_msat < MIN_AMOUNT_MSAT {
			cancelWrappedInvoice(p.Hash)
			return
		}
	}
	params := struct {
		Invoice           string  `json:"payment_request"`
		AmtMsat           uint64  `json:"amt_msat,omitempty,string"`
		TimeoutSeconds    int64   `json:"timeout_seconds"`
		FeeLimitMsat      uint64  `json:"fee_limit_msat,string"`
		NoInflightUpdates bool    `json:"no_inflight_updates"`
		CltvLimit         int32   `json:"cltv_limit"`
		Amp               bool    `json:"amp"`
		TimePref          float64 `json:"time_pref"`
	}{
		Invoice:           original_invoice,
		AmtMsat:           amt_msat,
		TimeoutSeconds:    p.Expiry,
		FeeLimitMsat:      max_fee_msat,
		NoInflightUpdates: true,
		CltvLimit:         int32(p.CltvExpiry - CLTV_DELTA_ALPHA),
		Amp:               false,
		TimePref:          0.9,
	}

	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", macaroon)
	loc := *lndHost
	if loc.Scheme == "https" {
		loc.Scheme = "wss"
	} else {
		loc.Scheme = "ws"
	}
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
		log.Println("Error while dialing socket for payment status:", p, err)
		return
	}

	err = websocket.JSON.Send(ws, params)
	if err != nil {
		log.Println("Error while dialing socket for payment status:", p, err)
		return
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
			log.Println("Error while receiving from socket for payment status:", p, err)
			return
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
			log.Println("Unknown payment status:", message.Result.Status, p)
		}

		if err == io.EOF {
			log.Println("Unexpected EOF while watching invoice")
			continue
		}
	}

	preimage2, err := hex.DecodeString(preimage)
	if err != nil {
		log.Panicln("Error decoding preimage", err)
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
	if err := dec.Decode(&x); err != nil && err != io.EOF {
		log.Panicln(err)
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		log.Println(fmt.Errorf("Unknown v2/invoices/settle response: %#v", x))
	}
}

func wrap(invoice string, max_fee_msat uint64) (string, error) {
	p, err := decodePaymentRequest(invoice)
	if err != nil {
		return "", err
	}
	q, err := wrapPaymentRequest(p, max_fee_msat)
	if err != nil {
		return "", err
	}
	i, err := addWrappedInvoice(q)
	if err != nil {
		return "", err
	}
	go watchWrappedInvoice(q, invoice, max_fee_msat)
	return i, nil
}

var validPath = regexp.MustCompile("^/api/(lnbc.*1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)")

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	m := validPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}

	var max_fee_msat uint64
	max_fee_msat_string := r.URL.Query().Get("routing_msat")
	if max_fee_msat_string != "" {
		var err error
		max_fee_msat, err = strconv.ParseUint(max_fee_msat_string, 10, 64)
		if err != nil {
			http.Error(w, "Invalid custom routing budget", http.StatusBadRequest)
			return
		}
		if max_fee_msat < MIN_CUSTOM_FEE_MSAT {
			http.Error(w, "Custom routing budget too small", http.StatusBadRequest)
			return
		}
	}
	i, err := wrap(m[1], max_fee_msat)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", i)
}

func specApiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")

	var x map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&x)
	if err != nil {
		b, _ := io.ReadAll(r.Body)
		log.Println("Body is not JSON object:", b)
		json.NewEncoder(w).Encode(makeJsonError("Body is not JSON object"))
		return
	}
	invoice, ok := x["invoice"]
	if !ok {
		json.NewEncoder(w).Encode(makeJsonError("Body needs an invoice field"))
		return
	}
	invoice_string, ok := invoice.(string)
	if !ok {
		json.NewEncoder(w).Encode(makeJsonError("Invoice field must be a string"))
		return
	}

	p, err := decodePaymentRequest(invoice_string)
	if err != nil {
		log.Println("Invalid invoice", err)
		json.NewEncoder(w).Encode(makeJsonError("Invalid invoice"))
		return
	}

	var max_fee_msat uint64
	if routing_msat, ok := x["routing_msat"]; ok {
		routing_msat_string, ok := routing_msat.(string)
		if !ok {
			json.NewEncoder(w).Encode(makeJsonError("Routing budget field must be a string"))
			return
		}
		max_fee_msat, err = strconv.ParseUint(routing_msat_string, 10, 64)
		if err != nil {
			json.NewEncoder(w).Encode(makeJsonError("Invalid routing budget"))
			return
		}
		if max_fee_msat < MIN_CUSTOM_FEE_MSAT {
			json.NewEncoder(w).Encode(makeJsonError("Routing budget too small"))
			return
		}
	}

	if description, ok := x["description"]; ok {
		description_string, ok := description.(string)
		if !ok {
			json.NewEncoder(w).Encode(makeJsonError("Description field must be a string"))
			return
		}
		p.Description = description_string
		p.DescriptionHash = ""
	}

	if description_hash, ok := x["description_hash"]; ok {
		description_hash_string, ok := description_hash.(string)
		if !ok {
			json.NewEncoder(w).Encode(makeJsonError("Description hash field must be a string"))
			return
		}
		p.DescriptionHash = description_hash_string
		p.Description = ""
	}

	q, err := wrapPaymentRequest(p, max_fee_msat)
	if err != nil {
		log.Println("Error while wrapping", err)
		json.NewEncoder(w).Encode(makeJsonError("Internal error"))
		return
	}

	wrapped_invoice, err := addWrappedInvoice(q)
	if err != nil {
		log.Println("Error while adding wrapped", err)
		json.NewEncoder(w).Encode(makeJsonError("Internal error"))
		return
	}

	go watchWrappedInvoice(q, invoice_string, max_fee_msat)

	json.NewEncoder(w).Encode(struct {
		WrappedInvoice string `json:"proxy_invoice"`
	}{
		WrappedInvoice: wrapped_invoice,
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

	lndClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: lndTlsConfig,
		},
	}

	http.HandleFunc("/spec", specApiHandler)
	http.HandleFunc("/api/", apiHandler)

	log.Fatalln(http.ListenAndServe("localhost:"+*httpPort, nil))
}
