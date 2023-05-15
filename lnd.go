package lnproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/websocket"
)

type Lnd struct {
	Host      *url.URL
	Client    *http.Client
	TlsConfig *tls.Config
	Macaroon  string
}

func (lnd *Lnd) DecodeInvoice(invoice string) (*DecodedInvoice, error) {
	req, err := http.NewRequest(
		"GET",
		lnd.Host.JoinPath("v1/payreq", invoice).String(),
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Grpc-Metadata-macaroon", lnd.Macaroon)

	resp, err := lnd.Client.Do(req)
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
	p := DecodedInvoice{}
	err = dec.Decode(&p)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &p, nil
}

func (lnd *Lnd) AddInvoice(p InvoiceParameters) (string, error) {
	params, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(params)
	req, err := http.NewRequest(
		"POST",
		lnd.Host.JoinPath("v2/invoices/hodl").String(),
		buf,
	)
	if err != nil {
		return "", err
	}
	req.Header.Add("Grpc-Metadata-macaroon", lnd.Macaroon)
	resp, err := lnd.Client.Do(req)
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

func (lnd *Lnd) WatchInvoice(hash []byte) (uint64, error) {
	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", lnd.Macaroon)
	loc := *lnd.Host
	if loc.Scheme == "https" {
		loc.Scheme = "wss"
	} else {
		loc.Scheme = "ws"
	}
	origin := *lnd.Host
	origin.Scheme = "http"

	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc.JoinPath("v2/invoices/subscribe", base64.URLEncoding.EncodeToString(hash)),
		Origin:    &origin,
		TlsConfig: lnd.TlsConfig,
		Header:    header,
		Version:   13,
	})
	if err != nil {
		return 0, err
	}
	err = websocket.JSON.Send(ws, struct{}{})
	if err != nil {
		return 0, err
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
			return 0, err
		}

		switch message.Result.State {
		case "OPEN":
			continue
		case "ACCEPTED":
			return message.Result.AmtPaidMsat, nil
		case "SETTLED", "CANCELED":
			return 0, fmt.Errorf("Invoice %s before payment.\n", message.Result.State)
		default:
			return 0, fmt.Errorf("Unknown invoice status %s.\n", message.Result.State)
		}

	}
}

func (lnd *Lnd) CancelInvoice(hash []byte) error {
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
		lnd.Host.JoinPath("v2/invoices/cancel").String(),
		buf,
	)
	if err != nil {
		return err
	}
	req.Header.Add("Grpc-Metadata-macaroon", lnd.Macaroon)
	resp, err := lnd.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		return fmt.Errorf("Unknown v2/invoices/cancel error: %v\n", x)
	}
	dec := json.NewDecoder(resp.Body)
	var x interface{}
	if err := dec.Decode(&x); err != nil && err != io.EOF {
		return fmt.Errorf("Unknown v2/invoices/cancel error: %v\n", err)
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		return fmt.Errorf("Unknown v2/invoices/cancel response: %v", x)
	}
	return nil
}

func (lnd *Lnd) PayInvoice(params PaymentParameters) ([]byte, error) {

	header := http.Header(make(map[string][]string, 1))
	header.Add("Grpc-Metadata-Macaroon", lnd.Macaroon)
	loc := *lnd.Host
	if loc.Scheme == "https" {
		loc.Scheme = "wss"
	} else {
		loc.Scheme = "ws"
	}
	q := url.Values{}
	q.Set("method", "POST")
	loc.RawQuery = q.Encode()
	origin := *lnd.Host
	origin.Scheme = "http"

	ws, err := websocket.DialConfig(&websocket.Config{
		Location:  loc.JoinPath("v2/router/send"),
		Origin:    &origin,
		TlsConfig: lnd.TlsConfig,
		Header:    header,
		Version:   13,
	})
	if err != nil {
		return nil, err
	}
	err = websocket.JSON.Send(ws, params)
	if err != nil {
		return nil, err
	}

	for {
		message := struct {
			Result struct {
				Status   string `json:"status"`
				PreImage string `json:"payment_preimage"`
			} `json:"result"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			return nil, err
		}

		switch message.Result.Status {
		case "FAILED":
			return nil, fmt.Errorf("Payment failed\n")
		case "UNKNOWN", "IN_FLIGHT", "":
			time.Sleep(500 * time.Millisecond)
		case "SUCCEEDED":
			log.Printf("preimage: %s\n", message.Result.PreImage)
			preimage, err := hex.DecodeString(message.Result.PreImage)
			if err != nil {
				log.Panicln(err)
			}
			return preimage, nil
		default:
			log.Println("Unknown payment status:", message.Result.Status, params)
		}

		if err == io.EOF {
			log.Println("Unexpected EOF while watching invoice")
			continue
		}
	}
}

func (lnd *Lnd) SettleInvoice(preimage []byte) error {
	params, err := json.Marshal(struct {
		PreImage []byte `json:"preimage"`
	}{
		PreImage: preimage,
	})
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(params)
	req, err := http.NewRequest(
		"POST",
		lnd.Host.JoinPath("v2/invoices/settle").String(),
		buf,
	)
	if err != nil {
		return err
	}
	req.Header.Add("Grpc-Metadata-macaroon", lnd.Macaroon)
	resp, err := lnd.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var x interface{}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&x)
		return fmt.Errorf("Unknown v2/invoices/settle error: %#v", x)
	}
	dec := json.NewDecoder(resp.Body)

	var x interface{}
	if err := dec.Decode(&x); err != nil && err != io.EOF {
		return err
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		return fmt.Errorf("Unknown v2/invoices/settle response: %#v", x)
	}
	return nil
}