package zkapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"reflect"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

const (
	solanaBackend  = "dagon.solana.groth16.v1"
	solanaSource   = "pyth_solana_receiver"
	lamportsPerSOL = 1_000_000_000
	maxSafeInteger = 1<<53 - 1
)

// solanaQuote is serverd's /v2/billing/quote body for native SOL. It is bound
// into every lease proof, so the exact bytes the server sent are what is proved.
type solanaQuote struct {
	Asset             string `json:"asset"`
	Source            string `json:"source"`
	CreditUnit        string `json:"credit_unit"`
	BaseUnitsPerAsset uint64 `json:"base_units_per_asset"`
	ChainID           string `json:"chain_id"`
	DeploymentBinding string `json:"deployment_binding"`
	Backend           string `json:"backend"`
	Network           string `json:"network"`
	Vault             string `json:"vault"`
	FeedID            string `json:"feed_id"`
	FeedAccount       string `json:"feed_account"`
	ReceiverProgram   string `json:"receiver_program"`
	Price             string `json:"price"`
	Exponent          int    `json:"exponent"`
	Confidence        string `json:"confidence"`
	PublishTime       uint64 `json:"publish_time"`
	ExpiresAt         uint64 `json:"expires_at"`
	PostedSlot        uint64 `json:"posted_slot"`
}

var errInvalidQuote = &Error{502, "invalid_solana_quote"}

// parseSolanaQuote decodes a quote strictly and checks it against the pinned
// deployment and the current time, mirroring serverd's own identity checks.
func parseSolanaQuote(raw []byte, pin *config.Solana, now uint64) (solanaQuote, error) {
	var q solanaQuote
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&q) != nil {
		return q, errInvalidQuote
	}
	if err := q.validate(pin, now, false); err != nil {
		return q, err
	}
	return q, nil
}

func (q solanaQuote) validate(pin *config.Solana, now uint64, allowExpired bool) error {
	price, ok1 := new(big.Int).SetString(q.Price, 10)
	confidence, ok2 := new(big.Int).SetString(q.Confidence, 10)
	if !ok1 || !ok2 || price.Sign() <= 0 || confidence.Sign() < 0 ||
		price.String() != q.Price || confidence.String() != q.Confidence ||
		price.BitLen() > 63 || confidence.BitLen() > 64 {
		return errInvalidQuote
	}
	lower := new(big.Int).Sub(price, confidence)
	limit := new(big.Int).Mul(price, new(big.Int).SetUint64(pin.PythMaxConfidenceBps))
	if q.Asset != "native_sol" || q.Source != solanaSource || q.CreditUnit != "lamports" ||
		q.BaseUnitsPerAsset != lamportsPerSOL || q.ChainID != pin.ChainID ||
		!config.SameFelt(q.DeploymentBinding, pin.ProtocolBinding) || q.Backend != solanaBackend ||
		q.Network != pin.Cluster || q.Vault != pin.VaultState || !config.SameFelt(q.FeedID, pin.PythFeedID) ||
		q.FeedAccount != pin.PythPriceAccount || q.ReceiverProgram != pin.PythReceiverProgram ||
		q.Exponent < -18 || q.Exponent > 18 || q.PublishTime == 0 || q.PostedSlot == 0 ||
		q.ExpiresAt != q.PublishTime+pin.PythMaxAgeSeconds || q.PublishTime > now ||
		(!allowExpired && q.ExpiresAt <= now) || lower.Sign() <= 0 ||
		new(big.Int).Mul(confidence, big.NewInt(10_000)).Cmp(limit) > 0 {
		return errInvalidQuote
	}
	return nil
}

// ratio is the lower-bound price (price minus confidence) in lamport-conversion
// form: USD per SOL = num/den. Conversion is exact integer arithmetic.
func (q solanaQuote) ratio() (num, den *big.Int) {
	price, _ := new(big.Int).SetString(q.Price, 10)
	confidence, _ := new(big.Int).SetString(q.Confidence, 10)
	num = price.Sub(price, confidence)
	den = big.NewInt(1)
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(abs(q.Exponent))), nil)
	if q.Exponent < 0 {
		den = scale
	} else {
		num.Mul(num, scale)
	}
	return num, den
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// unitsForMicroUSD is the smallest lamport amount worth at least micros micro-USD.
func (q solanaQuote) unitsForMicroUSD(micros uint64) (uint64, error) {
	num, den := q.ratio()
	top := new(big.Int).Mul(new(big.Int).SetUint64(micros), big.NewInt(lamportsPerSOL))
	top.Mul(top, den)
	bottom := new(big.Int).Mul(num, big.NewInt(1_000_000))
	top.Add(top, bottom).Sub(top, big.NewInt(1))
	units := top.Div(top, bottom)
	if micros == 0 || units.Sign() <= 0 || !units.IsInt64() || units.Int64() > maxSafeInteger {
		return 0, &Error{http.StatusBadRequest, "invalid_lease_limit"}
	}
	return units.Uint64(), nil
}

// microUSDForUnits floors the USD value of a lamport amount, as serverd does.
func (q solanaQuote) microUSDForUnits(units uint64) uint64 {
	num, den := q.ratio()
	value := new(big.Int).Mul(new(big.Int).SetUint64(units), num)
	value.Mul(value, big.NewInt(1_000_000))
	value.Div(value, new(big.Int).Mul(big.NewInt(lamportsPerSOL), den))
	return value.Uint64()
}

// sameQuoteJSON compares two quotes structurally, ignoring key order and case
// of hex strings, as the browser SDK's sameNativeQuote does.
func sameQuoteJSON(left, right []byte) bool {
	decode := func(raw []byte, into *map[string]any) bool {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		return d.Decode(into) == nil
	}
	var a, b map[string]any
	if !decode(left, &a) || !decode(right, &b) || len(a) == 0 {
		return false
	}
	lower := func(m map[string]any) {
		for key, value := range m {
			if text, ok := value.(string); ok {
				m[key] = strings.ToLower(text)
			}
		}
	}
	lower(a)
	lower(b)
	return reflect.DeepEqual(a, b)
}

var errNoQuote = errors.New("request carries no billing quote")

// quoteOfRequest extracts the quote proved into a prepared request's payload.
func quoteOfRequest(request json.RawMessage) (json.RawMessage, error) {
	var wire struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(request, &wire) != nil {
		return nil, errNoQuote
	}
	return quoteOfPayload(wire.Payload)
}

func quoteOfPayload(payload string) (json.RawMessage, error) {
	var body struct {
		Mode  string          `json:"mode"`
		Quote json.RawMessage `json:"billing_quote"`
	}
	if json.Unmarshal([]byte(payload), &body) != nil || len(body.Quote) == 0 {
		return nil, errNoQuote
	}
	return body.Quote, nil
}
