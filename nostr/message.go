package nostr

import (
	"encoding/json"

	relay "github.com/lnproxy/lnproxy-relay"
)

// Request is the decrypted plaintext of a kind 21821 wrap request. It embeds the
// base protocol ProxyParameters and adds the method and desired output format.
type Request struct {
	Method          string  `json:"method"`
	RequestID       string  `json:"request_id,omitempty"`
	ProviderPubkey  string  `json:"provider_pubkey,omitempty"`
	Invoice         string  `json:"invoice"`
	RoutingMsat     *uint64 `json:"routing_msat,string,omitempty"`
	Description     *string `json:"description,omitempty"`
	DescriptionHash *string `json:"description_hash,omitempty"`
	Wrap            string  `json:"wrap,omitempty"`
}

// MethodWrap is the only method defined in this protocol version.
const MethodWrap = "wrap"

// WrapFeature maps a request "wrap" output format to the feature flag a
// provider must advertise to serve it. An empty or "bolt11" value maps to
// FeatureWrapBolt11.
func WrapFeature(wrap string) string {
	switch wrap {
	case "", "bolt11":
		return FeatureWrapBolt11
	case "bolt11_blinded":
		return FeatureWrapBolt11Blinded
	case "bolt12":
		return FeatureWrapBolt12
	default:
		return wrap
	}
}

// ProxyParameters converts a decrypted request into the base protocol
// parameters consumed by relay.Relay.OpenCircuit.
func (r Request) ProxyParameters() relay.ProxyParameters {
	return relay.ProxyParameters{
		Invoice:         r.Invoice,
		RoutingMsat:     r.RoutingMsat,
		Description:     r.Description,
		DescriptionHash: r.DescriptionHash,
	}
}

// Response is the decrypted plaintext of a kind 21822 wrap response. Exactly one
// of ProxyInvoice or (Status, Reason) is set, matching the base HTTP API.
type Response struct {
	RequestID    string `json:"request_id,omitempty"`
	ProxyInvoice string `json:"proxy_invoice,omitempty"`
	Status       string `json:"status,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// errorResponse builds an ERROR response with the given reason.
func errorResponse(reason string) Response {
	return Response{Status: "ERROR", Reason: reason}
}

// MarshalResponse encodes a Response to its JSON plaintext form.
func MarshalResponse(resp Response) (string, error) {
	b, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
