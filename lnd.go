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
		err = dec.Decode(&x)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("v1/payreq response: %#v", x)
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
		err = dec.Decode(&x)
		if err != nil {
			return "", err
		}
		if x, ok := x.(map[string]interface{}); ok {
			if x["message"] == "invoice with payment hash already exists" {
				return "", PaymentHashExists
			}
		}
		return "", fmt.Errorf("v2/invoices/hodl  response: %#v", x)
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
	defer ws.Close()
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
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			return 0, err
		}
		if message.Error.Message != "" {
			return 0, fmt.Errorf("v2/invoices/subscribe response: %s", message.Error.Message)
		}

		switch message.Result.State {
		case "OPEN":
			time.Sleep(500 * time.Millisecond)
		case "ACCEPTED":
			return message.Result.AmtPaidMsat, nil
		case "SETTLED", "CANCELED":
			return message.Result.AmtPaidMsat, fmt.Errorf("invoice %s before payment", message.Result.State)
		default:
			return 0, fmt.Errorf("v2/invoices/subscribe unhandled state: %s", message.Result.State)
		}

		if err == io.EOF {
			return 0, err
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

	var x interface{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&x)
	if err != nil && err != io.EOF {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("v2/invoices/cancel response: %v\n", x)
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		return fmt.Errorf("v2/invoices/cancel unhandled response: %v\n", x)
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
	defer ws.Close()
	err = websocket.JSON.Send(ws, struct {
		PaymentParameters
		NoInflightUpdates bool    `json:"no_inflight_updates"`
		Amp               bool    `json:"amp"`
		TimePref          float64 `json:"time_pref"`
	}{
		PaymentParameters: params,
		NoInflightUpdates: true,
		Amp:               false,
		TimePref:          0.9,
	})
	if err != nil {
		return nil, err
	}
	for {
		message := struct {
			Result struct {
				Status        string `json:"status"`
				PreImage      string `json:"payment_preimage"`
				FailureReason string `json:"failure_reason"`
			} `json:"result"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}{}
		err = websocket.JSON.Receive(ws, &message)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if message.Error.Message != "" {
			return nil, fmt.Errorf("v2/router/send response: %s", message.Error.Message)
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
			return nil, fmt.Errorf("v2/router/send unhandled status: %s", message.Result.Status)
		}

		if err == io.EOF {
			return nil, err
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

	var x interface{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&x)
	if err != nil && err != io.EOF {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("v2/invoices/settle response: %#v", x)
	}
	if xmap, ok := x.(map[string]interface{}); !ok || len(xmap) != 0 {
		return fmt.Errorf("v2/invoices/settle unhandled response: %#v", x)
	}
	return nil
}
