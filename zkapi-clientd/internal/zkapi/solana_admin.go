package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ServeAdminHTTP is mounted behind the API bearer, browser-origin and owner
// management-token checks, like the Ethereum funding handler. It serves lease
// export, early settlement and status for a native-SOL wallet.
func (w *SolanaWallet) ServeAdminHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		rw.WriteHeader(http.StatusUnsupportedMediaType)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "JSON required"})
		return
	}
	decode := func(body any) error { return decodeJSON(http.MaxBytesReader(rw, r.Body, 1024), body) }
	var result any
	var err error
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/admin/solana/status":
		result = w.Status()
	case r.Method == http.MethodPost && r.URL.Path == "/admin/lease/export":
		var body struct {
			LimitMicroUSD uint64 `json:"request_limit_micro_usd"`
			Confirm       bool   `json:"confirm"`
		}
		if err = decode(&body); err == nil {
			if !body.Confirm {
				err = errors.New("lease export requires explicit confirmation")
			} else {
				result, err = w.ExportLease(ctx, body.LimitMicroUSD)
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == "/admin/lease/settle":
		var body struct {
			Confirm bool `json:"confirm"`
		}
		if err = decode(&body); err == nil {
			if !body.Confirm {
				err = errors.New("closing the lease requires explicit confirmation")
			} else {
				result, err = w.Settle(ctx, true)
			}
		}
	default:
		rw.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "unknown management endpoint"})
		return
	}
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(rw).Encode(result)
}
