package lnproxy

type LN interface {
	DecodeInvoice(string) (*DecodedInvoice, error)
	AddInvoice(InvoiceParameters) (string, error)
	WatchInvoice([]byte) (uint64, error)
	CancelInvoice([]byte) error
	PayInvoice(p PaymentParameters) ([]byte, error)
	SettleInvoice([]byte) error
}

type DecodedInvoice struct {
	PaymentHash     string `json:"payment_hash"`
	Timestamp       uint64 `json:"timestamp,string"`
	Expiry          uint64 `json:"expiry,string"`
	Description     string `json:"description"`
	DescriptionHash string `json:"description_hash"`
	NumMsat         uint64 `json:"num_msat,string"`
	CltvExpiry      uint64 `json:"cltv_expiry,string"`
	Features        map[string]struct {
		Name       string `json:"name"`
		IsRequired bool   `json:"is_required"`
		IsKnown    bool   `json:"is_known"`
	} `json:"features"`
}

type InvoiceParameters struct {
	Memo            string `json:"memo,omitempty"`
	Hash            []byte `json:"hash"`
	ValueMsat       uint64 `json:"value_msat,string"`
	DescriptionHash []byte `json:"description_hash,omitempty"`
	Expiry          uint64 `json:"expiry,string"`
	CltvExpiry      uint64 `json:"cltv_expiry,string"`
}

type PaymentParameters struct {
	Invoice           string  `json:"payment_request"`
	AmtMsat           uint64  `json:"amt_msat,omitempty,string"`
	TimeoutSeconds    uint64  `json:"timeout_seconds"`
	FeeLimitMsat      uint64  `json:"fee_limit_msat,string"`
	NoInflightUpdates bool    `json:"no_inflight_updates"`
	CltvLimit         uint64  `json:"cltv_limit"`
	Amp               bool    `json:"amp"`
	TimePref          float64 `json:"time_pref"`
}
