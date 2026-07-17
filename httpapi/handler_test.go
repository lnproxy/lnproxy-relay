package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lnproxy/lnproxy-relay/nostr"
)

type recordingWrapper struct {
	request  nostr.Request
	response nostr.Response
}

type blockingWrapper struct {
	started chan struct{}
	release chan struct{}
}

func (w *blockingWrapper) Wrap(request nostr.Request) nostr.Response {
	close(w.started)
	<-w.release
	return nostr.Response{RequestID: request.RequestID, ProxyInvoice: "lnbc-proxy"}
}

func (w *recordingWrapper) Wrap(request nostr.Request) nostr.Response {
	w.request = request
	return w.response
}

func TestHandlerWrapsDirectRequest(t *testing.T) {
	requestID := strings.Repeat("a", 64)
	wrapper := &recordingWrapper{response: nostr.Response{RequestID: requestID, ProxyInvoice: "lnbc-proxy"}}
	body := bytes.NewBufferString(`{"method":"wrap","request_id":"` + requestID + `","invoice":"lnbc1...","wrap":"bolt11"}`)
	req := httptest.NewRequest(http.MethodPost, "/spec", body)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	NewHandler(wrapper).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if wrapper.request.RequestID != requestID || wrapper.request.Invoice != "lnbc1..." {
		t.Fatalf("unexpected request: %+v", wrapper.request)
	}
	var response nostr.Response
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.RequestID != requestID || response.ProxyInvoice != "lnbc-proxy" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestHandlerAnswersCORSPreflight(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/spec", nil)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "X-Requested-With, Content-Type")
	recorder := httptest.NewRecorder()

	NewHandler(&recordingWrapper{}).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodPost) {
		t.Fatalf("Access-Control-Allow-Methods = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-Requested-With") {
		t.Fatalf("Access-Control-Allow-Headers = %q", got)
	}
}

func TestHandlerRejectsMalformedAndOversizedBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed", body: "{"},
		{name: "multiple objects", body: `{}` + `{}`},
		{name: "oversized", body: `{"invoice":"` + strings.Repeat("x", maxRequestBody) + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(test.body))
			NewHandler(&recordingWrapper{}).ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHandlerRejectsOtherMethods(t *testing.T) {
	recorder := httptest.NewRecorder()
	NewHandler(&recordingWrapper{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/spec", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandlerCanRequireRequestID(t *testing.T) {
	wrapper := &recordingWrapper{}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(`{"invoice":"lnbc1..."}`))
	NewHandlerWithOptions(wrapper, Options{RequireRequestID: true}).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response nostr.Response
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "ERROR" || response.Reason != "request_id required" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if wrapper.request.Invoice != "" {
		t.Fatal("wrapper was called without a request ID")
	}
}

func TestHandlerRejectsMismatchedProviderBeforeAdmission(t *testing.T) {
	requestID := strings.Repeat("a", 64)
	wrapper := &recordingWrapper{}
	handler := NewHandlerWithOptions(wrapper, Options{
		ProviderPubkey:     strings.Repeat("b", 64),
		MinRequestInterval: time.Hour,
		RequestBurst:       1,
	})

	for range 2 {
		body := `{"request_id":"` + requestID + `","provider_pubkey":"` + strings.Repeat("c", 64) + `","invoice":"lnbc1..."}`
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
		}
		var response nostr.Response
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.Status != "ERROR" || response.Reason != "provider_pubkey mismatch" || response.RequestID != requestID {
			t.Fatalf("unexpected response: %+v", response)
		}
	}
	if wrapper.request.Invoice != "" {
		t.Fatal("mismatched provider request reached wrapper")
	}
}

func TestHandlerBoundsConcurrentRequests(t *testing.T) {
	wrapper := &blockingWrapper{started: make(chan struct{}), release: make(chan struct{})}
	handler := NewHandlerWithOptions(wrapper, Options{MaxConcurrent: 1})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(`{"invoice":"first"}`)))
	}()
	<-wrapper.started

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(`{"invoice":"second"}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	close(wrapper.release)
	<-firstDone
}

func TestHandlerRateLimitsDirectRequests(t *testing.T) {
	handler := NewHandlerWithOptions(&recordingWrapper{}, Options{
		MinRequestInterval: time.Hour,
		RequestBurst:       1,
	})

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(`{"invoice":"first"}`)))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusOK)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(`{"invoice":"second"}`)))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestHandlerRateLimitDoesNotLetOneSourceStarveOthers(t *testing.T) {
	handler := NewHandlerWithOptions(&recordingWrapper{}, Options{
		MinRequestInterval: time.Hour,
		RequestBurst:       1,
	})

	request := func(remoteAddress, invoice string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/spec", strings.NewReader(`{"invoice":"`+invoice+`"}`))
		req.RemoteAddr = remoteAddress
		handler.ServeHTTP(recorder, req)
		return recorder
	}
	if got := request("198.51.100.1:1000", "attacker-first").Code; got != http.StatusOK {
		t.Fatalf("first attacker status = %d, want %d", got, http.StatusOK)
	}
	if got := request("198.51.100.1:1001", "attacker-second").Code; got != http.StatusTooManyRequests {
		t.Fatalf("second attacker status = %d, want %d", got, http.StatusTooManyRequests)
	}
	if got := request("198.51.100.2:1000", "honest").Code; got != http.StatusOK {
		t.Fatalf("honest source status = %d, want %d", got, http.StatusOK)
	}
}

func TestTokenBucketRefillsWithoutLosingPartialTokens(t *testing.T) {
	bucket := newTokenBucket(time.Second, 2)
	now := time.Unix(1_700_000_000, 0)
	if !bucket.allow(now) || !bucket.allow(now) {
		t.Fatal("token bucket rejected its initial burst")
	}
	if bucket.allow(now) {
		t.Fatal("token bucket exceeded its initial burst")
	}
	if bucket.allow(now.Add(500 * time.Millisecond)) {
		t.Fatal("token bucket refilled a full token too early")
	}
	if !bucket.allow(now.Add(time.Second)) {
		t.Fatal("token bucket lost partial refill after a denied request")
	}
	if bucket.allow(now.Add(1500 * time.Millisecond)) {
		t.Fatal("token bucket allowed a request with only a partial token")
	}
	if !bucket.allow(now.Add(2 * time.Second)) {
		t.Fatal("token bucket did not refill the next token")
	}
}
