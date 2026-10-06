package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestExportLeaseReturnsKeyOutsideReuseCacheAndSettlesAtExpiry(t *testing.T) {
	upstream := httptest.NewTLSServer(http.NotFoundHandler())
	defer upstream.Close()
	var leases atomic.Int32
	var requested []uint64
	expires := time.Now().Add(6 * time.Hour).Unix()
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Limit uint64 `json:"request_limit_micro_usd"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		requested = append(requested, body.Limit)
		_ = json.NewEncoder(w).Encode(map[string]any{"api_key": fmt.Sprintf("exported-key-%d", leases.Add(1)), "base_url": upstream.URL, "expires_at": expires, "verified": true, "verification_status": "verified"})
	}, upstream)
	client.config.KeyReuseWindow = time.Minute
	lease, err := client.ExportLease(context.Background(), 5_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if lease.APIKey != "exported-key-1" || lease.ExpiresAt != uint64(expires) || lease.LimitMicroUSD != 5_000_000 || len(requested) != 1 || requested[0] != 5_000_000 {
		t.Fatalf("lease=%+v requested=%v", lease, requested)
	}
	if client.cachedLease != nil {
		t.Fatal("an exported key must never enter the in-memory reuse cache")
	}
	if want := time.Unix(expires-1, 0); !client.leaseGroup.until.Equal(want) {
		t.Fatalf("settlement scheduled at %v, want provider expiry %v", client.leaseGroup.until, want)
	}
	select {
	case client.requestSlot <- struct{}{}:
		<-client.requestSlot
	default:
		t.Fatal("export kept the request slot")
	}
}

func TestExportLeaseRejectsBadLimitsAndFailsFastWhilePending(t *testing.T) {
	upstream := httptest.NewTLSServer(http.NotFoundHandler())
	defer upstream.Close()
	var calls atomic.Int32
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"lease_pending"}`))
	}, upstream)
	for _, limit := range []uint64{0, MaxExportLimitMicroUSD + 1} {
		if _, err := client.ExportLease(context.Background(), limit); err == nil {
			t.Fatalf("limit %d accepted", limit)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid limits reached the companion")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	_, err := client.ExportLease(ctx, 1_000_000)
	var failure *Error
	if !errors.As(err, &failure) || failure.Status != http.StatusConflict || time.Since(started) > 2*time.Second || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d elapsed=%v", err, calls.Load(), time.Since(started))
	}
}
