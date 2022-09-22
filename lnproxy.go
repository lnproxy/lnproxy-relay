package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image/color"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/websocket"
)

const (
	EXPIRY_BUFFER = 600
	FEE_BASE_MSAT = 1000
	FEE_PPM = 6000
	CLTV_DELTA_ALPHA = 3
	CLTV_DELTA_BETA = 6
	// Should be set to the same as the node's `--max-cltv-expiry` setting (default: 2016)
	MAX_CLTV_DELTA = 2016

	// setup in /etc/tor/torrc
	httpPort = 
	// Whatever you want
	httpsPort = 
	// grep restlisten ~/.lnd/lnd.conf
	lndHost    = 
	lndPort = 
	// lncli bakemacaroon --timeout 3600 \
	//   uri:/lnrpc.Lightning/DecodePayReq \
	//   uri:/invoicesrpc.Invoices/AddHoldInvoice \
	//   uri:/lnrpc.Lightning/LookupInvoice \
	//   uri:/invoicesrpc.Invoices/CancelInvoice \
	//   uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
	//   uri:/routerrpc.Router/SendPaymentV2 \
	//   uri:/invoicesrpc.Invoices/SettleInvoice
	macaroon = 
	// cat ~/.lnd/tls.cert
	lndCert  = 
)

type PaymentRequest struct {
	PaymentHash     string `json:"payment_hash"`
	Timestamp       int64  `json:"timestamp,string"`
	Expiry          int64  `json:"expiry,string"`
	Description     string `json:"description"`
	DescriptionHash string `json:"description_hash"`
	NumMsat         int64  `json:"num_msat,string"`
	CltvExpiry      int64  `json:"cltv_expiry,string"`
}

func decodePaymentRequest(invoice string) (*PaymentRequest, error) {
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d/v1/payreq/%s", lndHost, lndPort, invoice),
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)

	resp, err := LND.Do(req)
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
	q.CltvExpiry = p.CltvExpiry * CLTV_DELTA_BETA + CLTV_DELTA_ALPHA
	if q.CltvExpiry >= MAX_CLTV_DELTA {
		err = fmt.Errorf("cltv_expiry is too long")
		return nil, err
	}
	return &q, nil
}

func QR(invoice string) string {
	q, err := qrcode.New(strings.ToUpper(invoice), qrcode.Medium)
	if err != nil {
		log.Panicln(err)
	}
	q.BackgroundColor = color.Transparent
	b, err := q.PNG(-8)
	if err != nil {
		log.Panicln(err)
	}
	return base64.StdEncoding.EncodeToString(b)
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
		fmt.Sprintf("https://%s:%d/v2/invoices/hodl", lndHost, lndPort),
		buf,
	)
	if err != nil {
		return "", err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := LND.Do(req)
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
		fmt.Sprintf("https://%s:%d/v1/invoice/%s", lndHost, lndPort, hex.EncodeToString(hash)),
		nil,
	)
	if err != nil {
		return "", err
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)

	resp, err := LND.Do(req)
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
	loc, err := url.Parse(fmt.Sprintf(
		"wss://%s:%d/v2/invoices/subscribe/%s",
		lndHost, lndPort, base64.URLEncoding.EncodeToString(p.Hash),
	))
	if err != nil {
		log.Panicln(err)
	}
	origin, err := url.Parse("http://" + lndHost)
	if err != nil {
		log.Panicln(err)
	}
	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc,
		Origin:    origin,
		TlsConfig: TlsConfig,
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
		fmt.Sprintf("https://%s:%d/v2/invoices/cancel", lndHost, lndPort),
		buf,
	)
	if err != nil {
		log.Panicln(err)
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := LND.Do(req)
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
	var msat int64
	if p.ValueMsat > 0 {
		msat = 0
	} else {
		msat = paid_msat - (paid_msat*FEE_PPM)/1_000_000
	}
	params := struct {
		Invoice           string  `json:"payment_request"`
		AmtMsat           int64   `json:"amt_msat,omitempty,string"`
		TimeoutSeconds    int64   `json:"timeout_seconds"`
		FeeLimitMsat      int64   `json:"fee_limit_msat,string"`
		NoInflightUpdates bool    `json:"no_inflight_updates"`
		TimePref          float64 `json:"time_pref"`
		CltvLimit         int32   `json:"cltv_limit"`
	}{
		Invoice:           original_invoice,
		AmtMsat:           msat,
		TimeoutSeconds:    p.Expiry - time.Now().Unix(),
		FeeLimitMsat:      (paid_msat * FEE_PPM) / 1_000_000,
		NoInflightUpdates: true,
		TimePref:          0.9,
		CltvLimit:         int32(p.CltvExpiry - CLTV_DELTA_ALPHA),
	}

	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", macaroon)
	loc, err := url.Parse(fmt.Sprintf("wss://%s:%d/v2/router/send?method=POST", lndHost, lndPort))
	if err != nil {
		log.Panicln(err)
	}
	origin, err := url.Parse("http://" + lndHost)
	if err != nil {
		log.Panicln(err)
	}
	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc,
		Origin:    origin,
		TlsConfig: TlsConfig,
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
			time.Sleep(500 * time.Millisecond)
			settleWrappedInvoice(p, paid_msat, original_invoice)
			return
		case "UNKNOWN", "IN_FLIGHT":
			break
		case "SUCCEEDED":
			preimage = message.Result.PreImage
			log.Printf("preimage (%d): %s\n", msat/1000, preimage)
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
		fmt.Sprintf("https://%s:%d/v2/invoices/settle", lndHost, lndPort),
		buf,
	)
	if err != nil {
		log.Panicln(err)
	}
	req.Header.Add("Grpc-Metadata-macaroon", macaroon)
	resp, err := LND.Do(req)
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
	go func() {
		time.Sleep(time.Duration(q.Expiry * 1_000_000_000))
		cancelWrappedInvoice(q.Hash)
	}()
	return i, nil
}

var templates = template.Must(template.ParseGlob("templates/*"))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "start", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	invoice := r.FormValue("body")
	invoice = strings.TrimSpace(invoice)
	invoice = strings.ToLower(invoice)
	invoice = strings.TrimPrefix(invoice, "lightning:")
	http.Redirect(w, r, r.URL.Path+"/"+invoice, http.StatusSeeOther)
}

var validPath = regexp.MustCompile("^/(wrap|api)/(lnbc[a-z0-9]+)$")

func wrapHandler(w http.ResponseWriter, r *http.Request) {
	m := validPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	i, err := wrap(m[2])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = templates.ExecuteTemplate(w, "wrap",
		struct {
			Invoice string
			AsQR    string
		}{
			Invoice: i,
			AsQR:    QR(i),
		},
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	m := validPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	i, err := wrap(m[2])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s\n", i)
}

func addNostrHeaders(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		h.ServeHTTP(w, r)
	}
}

var LND *http.Client
var TlsConfig *tls.Config

func main() {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(lndCert))
	TlsConfig = &tls.Config{RootCAs: caCertPool}
	LND = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: TlsConfig,
		},
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com", "www.example.com"),
		Cache:      autocert.DirCache("certs"),
	}

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
	http.Handle("/.well-known/", addNostrHeaders(http.StripPrefix("/.well-known/", http.FileServer(http.Dir("well-known")))))
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/wrap", redirectHandler)
	http.HandleFunc("/wrap/", wrapHandler)
	http.HandleFunc("/api/", apiHandler)

	server := &http.Server{
		Addr: fmt.Sprintf("localhost:%d", httpsPort),
		TLSConfig: certManager.TLSConfig(),
	}

	go http.ListenAndServe(fmt.Sprintf("localhost:%d", httpPort), nil)
	log.Panicln(server.ListenAndServeTLS("", ""))
}
