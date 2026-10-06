package zkapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
)

// MaxExportLimitMicroUSD bounds a client-side export request. The deployment's
// server enforces its own authoritative cap; this only rejects typos early.
const MaxExportLimitMicroUSD uint64 = 100_000_000

// ExportedLease is a bounded runtime key handed to an external service, such
// as an MCP client. It is returned once and never stored or logged here.
type ExportedLease struct {
	APIKey             string `json:"api_key"`
	BaseURL            string `json:"base_url"`
	ExpiresAt          uint64 `json:"expires_at"`
	LimitMicroUSD      uint64 `json:"request_limit_micro_usd"`
	VerificationStatus string `json:"verification_status"`
}

// ExportLease opens one lease with the caller-chosen spending cap and returns
// its key. Unlike Complete it never waits for a pending settlement: an exported
// key can live for hours, so a second export fails fast with lease_pending.
// The key is kept out of the in-memory reuse cache, and its settlement is
// scheduled for its real expiry rather than the short reuse window.
func (c *Client) ExportLease(ctx context.Context, limit uint64) (ExportedLease, error) {
	if limit == 0 || limit > MaxExportLimitMicroUSD {
		return ExportedLease{}, &Error{http.StatusBadRequest, "invalid_lease_limit"}
	}
	select {
	case c.requestSlot <- struct{}{}:
	case <-ctx.Done():
		return ExportedLease{}, ctx.Err()
	}
	defer func() { <-c.requestSlot }()
	if err := c.Check(ctx); err != nil {
		return ExportedLease{}, err
	}
	c.cachedLease = nil
	leaseBody, _ := json.Marshal(map[string]uint64{"request_limit_micro_usd": limit})
	raw, err := c.request(ctx, http.MethodPost, "/oa/v1/lease", leaseBody)
	if err != nil {
		return ExportedLease{}, err
	}
	lease, err := c.acceptLease(raw, limit)
	if err != nil {
		return ExportedLease{}, err
	}
	c.cachedLease = nil
	if c.leaseGroup != nil && c.leaseGroup.serial == lease.serial {
		c.leaseGroup.until = time.Unix(int64(lease.ExpiresAt)-1, 0)
	}
	activity.Report(ctx, activity.Event{Kind: activity.KeyFresh, Key: lease.serial})
	activity.Report(ctx, activity.Event{Kind: activity.KeyReleased, Key: lease.serial, Complete: true})
	return ExportedLease{APIKey: lease.APIKey, BaseURL: lease.BaseURL, ExpiresAt: lease.ExpiresAt, LimitMicroUSD: limit, VerificationStatus: lease.VerificationStatus}, nil
}
