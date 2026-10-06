package zkapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// MaxLeaseQuoteAttempts bounds quote/prove rounds after serverd's retriable
// native_quote_stale refusal, matching the browser SDK (MAX_STALE_QUOTE_ATTEMPTS).
const MaxLeaseQuoteAttempts = 4

const (
	solanaWalletVersion = 1
	maxServerBody       = 8 << 20
	// recoveryWait bounds how long one retirement call keeps retrying a server
	// answer that explicitly asks for it (usage not yet final).
	recoveryWait = 2 * time.Minute
)

// SolanaWallet is a native-SOL note plus the durable state of at most one open
// lease. Everything that must survive a crash lives in one atomically replaced,
// owner-only file: the note state, the pending-request journal (written BEFORE a
// proof leaves this process) and the issued lease's timing.
type SolanaWallet struct {
	pin    config.Solana
	path   string
	http   *http.Client
	prover SolanaProver
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	slot   chan struct{} // one wallet operation at a time; context-aware
	wake   chan struct{}
	file   solanaWalletFile
	mu     sync.Mutex // guards file for readers outside the slot
}

type solanaIdentity struct {
	ProgramID       string `json:"program_id"`
	VaultState      string `json:"vault_state"`
	GenesisHash     string `json:"genesis_hash"`
	ChainID         string `json:"chain_id"`
	ProtocolBinding string `json:"protocol_binding"`
}

type solanaLease struct {
	ClientRequestID  string  `json:"client_request_id"`
	ExpiresAt        uint64  `json:"expires_at"`
	SettleAfter      uint64  `json:"settle_after"`
	SpendingLimitUSD float64 `json:"spending_limit_usd"`
}

type solanaWalletFile struct {
	Version    int             `json:"version"`
	Deployment solanaIdentity  `json:"deployment"`
	Config     json.RawMessage `json:"config"`
	State      json.RawMessage `json:"state"`
	Journal    json.RawMessage `json:"journal,omitempty"`
	Lease      *solanaLease    `json:"lease,omitempty"`
}

// solanaNote is the non-secret view of the stored note state.
type solanaNote struct {
	NoteID          uint32      `json:"note_id"`
	ChainID         json.Number `json:"chain_id"`
	ContractAddress string      `json:"contract_address"`
	CurrentBalance  json.Number `json:"current_balance"`
}

// SolanaStatus is safe local metadata: no secrets and no request identifiers.
type SolanaStatus struct {
	HasNote        bool   `json:"has_note"`
	Balance        string `json:"private_balance_lamports,omitempty"`
	PendingRequest bool   `json:"pending_request"`
	LeaseExpiresAt uint64 `json:"lease_expires_at,omitempty"`
	SettleAfter    uint64 `json:"settle_after,omitempty"`
}

func solanaWalletPath(dir string, pin config.Solana) string {
	return filepath.Join(dir, "zkapi", "solana", pin.VaultState, "wallet.json")
}

func identityOf(pin config.Solana) solanaIdentity {
	return solanaIdentity{pin.ProgramID, pin.VaultState, pin.GenesisHash, pin.ChainID, pin.ProtocolBinding}
}

// ImportSolanaWallet stores an exported wallet ({"config","state"}) for the
// pinned deployment. It never overwrites an existing wallet.
func ImportSolanaWallet(dir string, pin config.Solana, exported []byte) error {
	var wire struct {
		Config  json.RawMessage `json:"config"`
		State   json.RawMessage `json:"state"`
		Journal json.RawMessage `json:"journal"`
	}
	if json.Unmarshal(exported, &wire) != nil || len(wire.Config) == 0 || len(wire.State) == 0 || bytes.Equal(wire.State, []byte("null")) {
		return errors.New("wallet export must contain a config and a funded note state")
	}
	if len(wire.Journal) != 0 && !bytes.Equal(wire.Journal, []byte("null")) {
		return errors.New("a wallet with a pending request cannot be imported; settle it first")
	}
	file := solanaWalletFile{Version: solanaWalletVersion, Deployment: identityOf(pin), Config: wire.Config, State: wire.State}
	if err := file.check(pin); err != nil {
		return err
	}
	path := solanaWalletPath(dir, pin)
	if _, err := os.Lstat(path); err == nil {
		return errors.New("a wallet already exists for this deployment")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return file.save(path)
}

// check ties the stored note to the pinned deployment, so a profile edit can
// never move a wallet to another vault.
func (f solanaWalletFile) check(pin config.Solana) error {
	if f.Version != solanaWalletVersion || f.Deployment != identityOf(pin) {
		return errors.New("wallet does not match the pinned Solana deployment")
	}
	var cfg struct {
		ProtocolVersion int         `json:"protocol_version"`
		LedgerBackend   string      `json:"ledger_backend"`
		ChainID         json.Number `json:"chain_id"`
		ContractAddress string      `json:"contract_address"`
	}
	if json.Unmarshal(f.Config, &cfg) != nil || cfg.ProtocolVersion != 2 || cfg.LedgerBackend != solanaBackend ||
		cfg.ChainID.String() != pin.ChainID || !config.SameFelt(cfg.ContractAddress, pin.ProtocolBinding) {
		return errors.New("wallet config does not match the pinned Solana deployment")
	}
	note, err := f.note()
	if err != nil {
		return err
	}
	if note.ChainID.String() != pin.ChainID || !config.SameFelt(note.ContractAddress, pin.ProtocolBinding) {
		return errors.New("wallet note does not match the pinned Solana deployment")
	}
	return nil
}

func (f solanaWalletFile) note() (solanaNote, error) {
	var note solanaNote
	if json.Unmarshal(f.State, &note) != nil {
		return note, errors.New("wallet note is unreadable")
	}
	if _, ok := new(big.Int).SetString(note.CurrentBalance.String(), 10); !ok {
		return note, errors.New("wallet note balance is invalid")
	}
	return note, nil
}

func (f solanaWalletFile) hasJournal() bool {
	return len(f.Journal) != 0 && !bytes.Equal(f.Journal, []byte("null"))
}

// save replaces the wallet file atomically and durably: a crash leaves either
// the old or the new complete file, never a mixture.
func (f solanaWalletFile) save(path string) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	return syncDirectoryChain(dir)
}

// OpenSolanaWallet loads the pinned deployment's wallet. A nil client uses a
// plain loopback-capable HTTP client; production callers pass their relay client.
func OpenSolanaWallet(dir string, pin config.Solana, client *http.Client, prover SolanaProver) (*SolanaWallet, error) {
	if err := pin.Validate(); err != nil {
		return nil, err
	}
	path := solanaWalletPath(dir, pin)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("no Solana wallet for this deployment; run zkapi-clientd solana import-wallet")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Solana wallet file must be a regular owner-only file (chmod 600)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file solanaWalletFile
	if json.Unmarshal(raw, &file) != nil {
		return nil, errors.New("Solana wallet file is unreadable")
	}
	if err := file.check(pin); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Minute, CheckRedirect: noRedirect}
	}
	return &SolanaWallet{
		pin: pin, path: path, http: client, prover: prover, now: time.Now, file: file,
		sleep: func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
		slot: make(chan struct{}, 1), wake: make(chan struct{}, 1),
	}, nil
}

// Status reports the saved wallet without touching the network.
func (w *SolanaWallet) Status() SolanaStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	status := SolanaStatus{PendingRequest: w.file.hasJournal()}
	if note, err := w.file.note(); err == nil {
		status.HasNote = true
		status.Balance = note.CurrentBalance.String()
	}
	if w.file.Lease != nil {
		status.LeaseExpiresAt, status.SettleAfter = w.file.Lease.ExpiresAt, w.file.Lease.SettleAfter
	}
	return status
}

// update persists a new durable state; the in-memory copy changes only after
// the file is safely on disk.
func (w *SolanaWallet) update(mutate func(*solanaWalletFile)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	next := w.file
	mutate(&next)
	if err := next.save(w.path); err != nil {
		return &Error{http.StatusInternalServerError, "wallet_storage_failed"}
	}
	w.file = next
	return nil
}

func (w *SolanaWallet) snapshot() solanaWalletFile {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file
}

func (w *SolanaWallet) acquire(ctx context.Context) (func(), error) {
	select {
	case w.slot <- struct{}{}:
		return func() { <-w.slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// serverError is a refusal decoded from serverd's error envelope.
type serverError struct {
	Status     int
	Code       string
	Retriable  bool
	RetryAfter time.Duration
}

func (e *serverError) Error() string {
	return fmt.Sprintf("zkAPI server refused (%d %s)", e.Status, e.Code)
}

func asServerError(err error) *serverError {
	var refusal *serverError
	if errors.As(err, &refusal) {
		return refusal
	}
	return nil
}

func (w *SolanaWallet) remote(ctx context.Context, method, base, path string, body []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := w.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{http.StatusBadGateway, "solana_server_unavailable"}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxServerBody+1))
	if err != nil || len(data) > maxServerBody {
		return nil, &Error{http.StatusBadGateway, "invalid_solana_server_response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		refusal := &serverError{Status: response.StatusCode}
		var envelope struct {
			Code       string `json:"error_code"`
			Retriable  bool   `json:"retriable"`
			RetryAfter uint64 `json:"retry_after_seconds"`
		}
		if json.Unmarshal(data, &envelope) == nil {
			refusal.Code, refusal.Retriable = envelope.Code, envelope.Retriable
			refusal.RetryAfter = time.Duration(min(envelope.RetryAfter, 60)) * time.Second
		}
		return nil, refusal
	}
	if !json.Valid(data) {
		return nil, &Error{http.StatusBadGateway, "invalid_solana_server_response"}
	}
	return data, nil
}

func (w *SolanaWallet) server(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	return w.remote(ctx, method, w.pin.ServerURL, path, body)
}

func (w *SolanaWallet) unix() uint64 { return uint64(w.now().Unix()) }

// checkAttestation pins the server's identity and signing keys before any proof
// is made for it.
func (w *SolanaWallet) checkAttestation(ctx context.Context) error {
	raw, err := w.server(ctx, http.MethodGet, "/v1/attestation", nil)
	if err != nil {
		return err
	}
	var att struct {
		ChainID         json.Number           `json:"chain_id"`
		ContractAddress string                `json:"contract_address"`
		State           struct{ X, Y string } `json:"state_signing_key"`
		Clearance       struct{ X, Y string } `json:"clearance_signing_key"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	same := config.SameFelt
	if d.Decode(&att) != nil || att.ChainID.String() != w.pin.ChainID || !same(att.ContractAddress, w.pin.ProtocolBinding) ||
		!same(att.State.X, w.pin.StateSigningKey.X) || !same(att.State.Y, w.pin.StateSigningKey.Y) ||
		!same(att.Clearance.X, w.pin.ClearanceSigningKey.X) || !same(att.Clearance.Y, w.pin.ClearanceSigningKey.Y) {
		return &Error{http.StatusBadGateway, "solana_deployment_mismatch"}
	}
	return nil
}

func (w *SolanaWallet) fetchQuote(ctx context.Context) (solanaQuote, json.RawMessage, error) {
	raw, err := w.server(ctx, http.MethodGet, "/v2/billing/quote", nil)
	if err != nil {
		return solanaQuote{}, nil, err
	}
	quote, err := parseSolanaQuote(raw, &w.pin, w.unix())
	if err != nil {
		return quote, nil, err
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return quote, nil, errInvalidQuote
	}
	return quote, compact.Bytes(), nil
}

func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b[:])
	return "zkapi-clientd-" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// withBudget sets the proof's per-request cap (the lease budget in lamports) in
// a copy of the stored wallet config, as the browser SDK does.
func withBudget(raw json.RawMessage, units uint64) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, errors.New("wallet config is unreadable")
	}
	fields["request_charge_cap"] = json.RawMessage(fmt.Sprint(units))
	return json.Marshal(fields)
}

// ExportLease opens one lease capped at limit micro-USD and returns its key.
// The key is returned once and never stored. It follows the SDK's lease flow:
// quote, prove (the quote is bound into the proof), POST, and on serverd's
// retriable native_quote_stale confirm nothing was accepted, then quote and
// prove again, at most MaxLeaseQuoteAttempts times. A proof is never sent twice
// after a refusal, and nothing new is proved while an earlier request's outcome
// is unknown.
func (w *SolanaWallet) ExportLease(ctx context.Context, limit uint64) (ExportedLease, error) {
	if limit == 0 || limit > MaxExportLimitMicroUSD {
		return ExportedLease{}, &Error{http.StatusBadRequest, "invalid_lease_limit"}
	}
	release, err := w.acquire(ctx)
	if err != nil {
		return ExportedLease{}, err
	}
	defer release()
	if err := w.recoverLocked(ctx); err != nil {
		return ExportedLease{}, err
	}
	if w.snapshot().hasJournal() {
		return ExportedLease{}, &Error{http.StatusConflict, "lease_pending"}
	}
	if err := w.checkAttestation(ctx); err != nil {
		return ExportedLease{}, err
	}
	for attempt := 1; attempt <= MaxLeaseQuoteAttempts; attempt++ {
		lease, retry, err := w.leaseOnce(ctx, limit)
		if err != nil {
			return ExportedLease{}, err
		}
		if !retry {
			return lease, nil
		}
	}
	return ExportedLease{}, &Error{http.StatusConflict, "native_quote_stale"}
}

// leaseOnce makes one quote/prove/POST round. retry is true only after serverd
// refused with native_quote_stale AND confirmed the request was never accepted.
func (w *SolanaWallet) leaseOnce(ctx context.Context, limit uint64) (ExportedLease, bool, error) {
	quote, quoteJSON, err := w.fetchQuote(ctx)
	if err != nil {
		return ExportedLease{}, false, err
	}
	units, err := quote.unitsForMicroUSD(limit)
	if err != nil {
		return ExportedLease{}, false, err
	}
	file := w.snapshot()
	note, err := file.note()
	if err != nil {
		return ExportedLease{}, false, err
	}
	balance, _ := new(big.Int).SetString(note.CurrentBalance.String(), 10)
	if units < w.pin.MinLeaseCredits {
		return ExportedLease{}, false, &Error{http.StatusBadRequest, "lease_below_deployment_minimum"}
	}
	if balance.Cmp(new(big.Int).SetUint64(units)) < 0 {
		return ExportedLease{}, false, &Error{http.StatusBadRequest, "insufficient_private_balance"}
	}
	snapshotRaw, err := w.remote(ctx, http.MethodGet, w.pin.IndexerURL, "/v1/tree/snapshot", nil)
	if err != nil {
		return ExportedLease{}, false, err
	}
	cfg, err := withBudget(file.Config, units)
	if err != nil {
		return ExportedLease{}, false, err
	}
	id, err := newRequestID()
	if err != nil {
		return ExportedLease{}, false, err
	}
	now := w.now()
	prepared, err := w.prover.Prepare(ctx, SolanaPrepareInput{
		Config: cfg, State: file.State, Snapshot: snapshotRaw, NoteID: note.NoteID,
		Payload:         `{"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":` + string(quoteJSON) + `}`,
		ClientRequestID: id, RequestTime: uint64(now.Unix()), CreatedAtMs: uint64(now.UnixMilli()),
	})
	if err != nil {
		return ExportedLease{}, false, err
	}
	if err := w.checkPrepared(prepared, id, quoteJSON); err != nil {
		return ExportedLease{}, false, err
	}
	// The journal must be durable BEFORE the proof leaves this process: a crash
	// after the POST must never lose the only record of a possibly accepted request.
	if err := w.update(func(f *solanaWalletFile) { f.Journal, f.Lease = prepared.Journal, nil }); err != nil {
		return ExportedLease{}, false, err
	}
	raw, err := w.server(ctx, http.MethodPost, "/v2/openrouter/leases", prepared.Request)
	if err != nil {
		refusal := asServerError(err)
		switch {
		case refusal != nil && refusal.Status == http.StatusConflict && refusal.Retriable && refusal.Code == "native_quote_stale":
			unaccepted, confirmErr := w.confirmUnaccepted(ctx, id, prepared.Request, quote.ExpiresAt)
			if confirmErr != nil || !unaccepted {
				return ExportedLease{}, false, &Error{http.StatusConflict, "native_quote_stale_unconfirmed"}
			}
			if err := w.update(func(f *solanaWalletFile) { f.Journal = nil }); err != nil {
				return ExportedLease{}, false, err
			}
			return ExportedLease{}, true, nil
		case refusal != nil && refusal.Code == "stale_root":
			// Rejected before any reservation; the next attempt reads a fresh tree.
			if err := w.update(func(f *solanaWalletFile) { f.Journal = nil }); err != nil {
				return ExportedLease{}, false, err
			}
			return ExportedLease{}, false, &Error{http.StatusConflict, "stale_root"}
		case refusal != nil && refusal.Status == http.StatusTooManyRequests:
			return ExportedLease{}, false, &Error{http.StatusTooManyRequests, "lease_rate_limited"}
		}
		// Any other failure may hide an accepted request. Keep the journal; the next
		// operation recovers it before proving anything new.
		return ExportedLease{}, false, &Error{http.StatusBadGateway, "lease_outcome_unknown"}
	}
	lease, err := w.acceptIssued(ctx, raw, id, quote, quoteJSON, units, limit)
	return lease, false, err
}

func (w *SolanaWallet) checkPrepared(prepared SolanaPrepared, id string, quoteJSON json.RawMessage) error {
	var journal struct {
		ClientRequestID string          `json:"client_request_id"`
		Prepared        json.RawMessage `json:"prepared_request"`
	}
	if json.Unmarshal(prepared.Journal, &journal) != nil || journal.ClientRequestID != id {
		return &Error{http.StatusBadGateway, "solana_prover_failed"}
	}
	proved, err := quoteOfRequest(prepared.Request)
	if err != nil || !sameQuoteJSON(proved, quoteJSON) || !sameJSON(journal.Prepared, prepared.Request) {
		return &Error{http.StatusBadGateway, "solana_prover_failed"}
	}
	return nil
}

func sameJSON(a, b []byte) bool {
	var left, right any
	da, db := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	da.UseNumber()
	db.UseNumber()
	return da.Decode(&left) == nil && db.Decode(&right) == nil && fmt.Sprint(left) == fmt.Sprint(right)
}

type issuedLease struct {
	Status           string          `json:"status"`
	ClientRequestID  string          `json:"client_request_id"`
	APIKey           string          `json:"api_key"`
	APIBase          string          `json:"openrouter_api_base"`
	ExpiresAt        uint64          `json:"expires_at"`
	SettleAfter      uint64          `json:"settle_after"`
	SpendingLimitUSD float64         `json:"spending_limit_usd"`
	KeySource        string          `json:"key_source"`
	Quote            json.RawMessage `json:"billing_quote"`
}

// acceptIssued records the lease's timing durably before the key is released,
// then checks it against what was proved. A lease that fails the checks is
// retired immediately (best effort) because nobody has seen its key.
func (w *SolanaWallet) acceptIssued(ctx context.Context, raw []byte, id string, quote solanaQuote, quoteJSON json.RawMessage, units, limit uint64) (ExportedLease, error) {
	var lease issuedLease
	if json.Unmarshal(raw, &lease) != nil || lease.ClientRequestID != id || lease.ExpiresAt == 0 || lease.SettleAfter < lease.ExpiresAt {
		return ExportedLease{}, &Error{http.StatusBadGateway, "invalid_solana_lease"}
	}
	if err := w.update(func(f *solanaWalletFile) {
		f.Lease = &solanaLease{ClientRequestID: id, ExpiresAt: lease.ExpiresAt, SettleAfter: lease.SettleAfter, SpendingLimitUSD: lease.SpendingLimitUSD}
	}); err != nil {
		return ExportedLease{}, err
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
	invalid := func() (ExportedLease, error) {
		_, _ = w.settleLocked(ctx, true)
		return ExportedLease{}, &Error{http.StatusBadGateway, "invalid_solana_lease"}
	}
	if lease.Status != "active" || lease.APIKey == "" || strings.ContainsAny(lease.APIKey, "\r\n \t") ||
		lease.ExpiresAt <= w.unix()+1 || lease.KeySource != "openrouter" ||
		!sameQuoteJSON(lease.Quote, quoteJSON) ||
		uint64(math.Round(lease.SpendingLimitUSD*1e6)) != quote.microUSDForUnits(units) ||
		quote.microUSDForUnits(units) != limit ||
		strings.TrimRight(lease.APIBase, "/") != strings.TrimRight(w.pin.InferenceBase, "/") {
		return invalid()
	}
	return ExportedLease{APIKey: lease.APIKey, BaseURL: lease.APIBase, ExpiresAt: lease.ExpiresAt, LimitMicroUSD: limit, VerificationStatus: "not-applicable"}, nil
}

// confirmUnaccepted asks serverd, under its issuance lock, whether this exact
// request was never accepted. While the quote could still be accepted it keeps
// asking until the quote expires; only a confirmed non-acceptance returns true.
func (w *SolanaWallet) confirmUnaccepted(ctx context.Context, id string, request json.RawMessage, quoteExpiresAt uint64) (bool, error) {
	var request2 struct {
		PayloadHash  string `json:"payload_hash"`
		PublicInputs struct {
			Nullifier string `json:"request_nullifier"`
		} `json:"public_inputs"`
	}
	if json.Unmarshal(request, &request2) != nil {
		return false, errors.New("unreadable request")
	}
	for {
		raw, err := w.server(ctx, http.MethodPost, "/v2/openrouter/leases/"+url.PathEscape(id)+"/expire", request)
		if err == nil {
			var answer struct {
				Status          string `json:"status"`
				ClientRequestID string `json:"client_request_id"`
				Nullifier       string `json:"request_nullifier"`
				PayloadHash     string `json:"payload_hash"`
			}
			if json.Unmarshal(raw, &answer) != nil || answer.ClientRequestID != id ||
				!config.SameFelt(answer.Nullifier, request2.PublicInputs.Nullifier) || !config.SameFelt(answer.PayloadHash, request2.PayloadHash) {
				return false, errors.New("mismatched expiry answer")
			}
			return answer.Status == "expired_unaccepted" || answer.Status == "superseded_unaccepted", nil
		}
		refusal := asServerError(err)
		if refusal == nil || refusal.Code != "lease_pending" || w.unix() > quoteExpiresAt+5 {
			return false, err
		}
		if err := w.sleep(ctx, 2*time.Second); err != nil {
			return false, err
		}
	}
}

// recoverLocked resolves an unfinished request left by a crash or an unknown
// outcome. It never proves anything new. It returns nil when the wallet has no
// journal afterwards, and a lease_pending error while the outcome or the key's
// lifetime is still open.
func (w *SolanaWallet) recoverLocked(ctx context.Context) error {
	file := w.snapshot()
	if !file.hasJournal() {
		return nil
	}
	var journal struct {
		ClientRequestID string          `json:"client_request_id"`
		Nullifier       string          `json:"nullifier"`
		Prepared        json.RawMessage `json:"prepared_request"`
		Hash            string          `json:"payload_hash"`
	}
	if json.Unmarshal(file.Journal, &journal) != nil || journal.ClientRequestID == "" {
		return &Error{http.StatusInternalServerError, "wallet_journal_unreadable"}
	}
	pending := &Error{http.StatusConflict, "lease_pending"}
	status, err := w.leaseStatus(ctx, journal.ClientRequestID)
	if err != nil {
		refusal := asServerError(err)
		if refusal == nil || refusal.Status != http.StatusNotFound {
			return err
		}
		// Unknown to the server's lease table: look the nullifier up, then fall
		// back to the quote-expiry handshake that proves non-acceptance.
		raw, err := w.server(ctx, http.MethodGet, "/v2/nullifiers/"+url.PathEscape(journal.Nullifier), nil)
		if err != nil {
			return err
		}
		var found struct {
			Status         string          `json:"status"`
			NullifierState string          `json:"nullifier_status"`
			Response       json.RawMessage `json:"request_response"`
		}
		if json.Unmarshal(raw, &found) != nil {
			return &Error{http.StatusBadGateway, "invalid_solana_server_response"}
		}
		if len(found.Response) != 0 && !bytes.Equal(found.Response, []byte("null")) {
			return w.installLocked(ctx)
		}
		if found.Status != "not_found" || found.NullifierState != "unknown" {
			return pending
		}
		quote, qerr := quoteOfRequest(journal.Prepared)
		var expires struct {
			ExpiresAt uint64 `json:"expires_at"`
		}
		if qerr != nil || json.Unmarshal(quote, &expires) != nil {
			return &Error{http.StatusInternalServerError, "wallet_journal_unreadable"}
		}
		unaccepted, err := w.confirmUnaccepted(ctx, journal.ClientRequestID, journal.Prepared, expires.ExpiresAt)
		if err != nil || !unaccepted {
			return pending
		}
		return w.update(func(f *solanaWalletFile) { f.Journal, f.Lease = nil, nil })
	}
	if status.Status == "finalized" {
		return w.installLocked(ctx)
	}
	// An open key. If this wallet issued it and it has not reached its settlement
	// time the key may still be in use elsewhere: leave it. Otherwise nobody holds
	// the key (lost before it was released) or it has expired: retire it now.
	if lease := file.Lease; lease != nil && lease.ClientRequestID == journal.ClientRequestID && w.unix() < lease.SettleAfter {
		return pending
	}
	if _, err := w.settleLocked(ctx, true); err != nil {
		return pending
	}
	return nil
}

type leaseStatus struct {
	Status      string   `json:"status"`
	SettleAfter uint64   `json:"settle_after"`
	ExpiresAt   uint64   `json:"expires_at"`
	ChargeUsage *float64 `json:"usage_usd"`
}

func (w *SolanaWallet) leaseStatus(ctx context.Context, id string) (leaseStatus, error) {
	raw, err := w.server(ctx, http.MethodGet, "/v2/openrouter/leases/"+url.PathEscape(id), nil)
	if err != nil {
		return leaseStatus{}, err
	}
	var status leaseStatus
	if json.Unmarshal(raw, &status) != nil || status.Status == "" {
		return status, &Error{http.StatusBadGateway, "invalid_solana_server_response"}
	}
	return status, nil
}

// SettleResult tells a caller whether the wallet is now free of a lease.
type SettleResult struct {
	Settled bool   `json:"settled"`
	Balance string `json:"private_balance_lamports,omitempty"`
}

// Settle closes the open lease now (force) or once its settlement time has
// passed, then installs the server-signed settlement into the note.
func (w *SolanaWallet) Settle(ctx context.Context, force bool) (SettleResult, error) {
	release, err := w.acquire(ctx)
	if err != nil {
		return SettleResult{}, err
	}
	defer release()
	return w.settleLocked(ctx, force)
}

func (w *SolanaWallet) settleLocked(ctx context.Context, force bool) (SettleResult, error) {
	file := w.snapshot()
	result := func() SettleResult {
		status := w.Status()
		return SettleResult{Settled: !status.PendingRequest, Balance: status.Balance}
	}
	if !file.hasJournal() {
		return result(), nil
	}
	if lease := file.Lease; lease != nil && !force && w.unix() < lease.SettleAfter {
		return result(), &Error{http.StatusConflict, "lease_pending"}
	}
	var journal struct {
		ClientRequestID string          `json:"client_request_id"`
		Prepared        json.RawMessage `json:"prepared_request"`
	}
	if json.Unmarshal(file.Journal, &journal) != nil {
		return result(), &Error{http.StatusInternalServerError, "wallet_journal_unreadable"}
	}
	deadline := w.now().Add(recoveryWait)
	for attempt := 1; ; attempt++ {
		raw, err := w.server(ctx, http.MethodPost, "/v2/openrouter/leases/"+url.PathEscape(journal.ClientRequestID), journal.Prepared)
		if err == nil {
			var status leaseStatus
			if json.Unmarshal(raw, &status) != nil || status.Status != "finalized" {
				return result(), &Error{http.StatusConflict, "lease_pending"}
			}
			break
		}
		refusal := asServerError(err)
		backoff := min(time.Duration(1<<min(attempt-1, 4))*time.Second, 10*time.Second)
		if refusal != nil {
			backoff = max(backoff, refusal.RetryAfter)
		}
		retriable := refusal != nil && (refusal.Code == "lease_settlement_pending" || refusal.Code == "lease_pending" || refusal.Status == http.StatusTooManyRequests)
		if !retriable || w.now().Add(backoff).After(deadline) {
			return result(), &Error{http.StatusConflict, "lease_pending"}
		}
		if err := w.sleep(ctx, backoff); err != nil {
			return result(), err
		}
	}
	if err := w.installLocked(ctx); err != nil {
		return result(), err
	}
	return result(), nil
}

// installLocked fetches the server-signed settlement, verifies it against the
// proved quote and the note state through the wallet helper, and replaces the
// note, clearing the journal and lease in one atomic write.
func (w *SolanaWallet) installLocked(ctx context.Context) error {
	file := w.snapshot()
	var journal struct {
		ClientRequestID string          `json:"client_request_id"`
		Prepared        json.RawMessage `json:"prepared_request"`
	}
	if json.Unmarshal(file.Journal, &journal) != nil {
		return &Error{http.StatusInternalServerError, "wallet_journal_unreadable"}
	}
	raw, err := w.server(ctx, http.MethodGet, "/v2/requests/"+url.PathEscape(journal.ClientRequestID), nil)
	if err != nil {
		return err
	}
	var recovery struct {
		Response json.RawMessage `json:"request_response"`
	}
	if json.Unmarshal(raw, &recovery) != nil || len(recovery.Response) == 0 || bytes.Equal(recovery.Response, []byte("null")) {
		return &Error{http.StatusConflict, "lease_pending"}
	}
	var response struct {
		Payload string `json:"response_payload"`
	}
	proved, err := quoteOfRequest(journal.Prepared)
	if err != nil || json.Unmarshal(recovery.Response, &response) != nil {
		return &Error{http.StatusBadGateway, "invalid_solana_settlement"}
	}
	settled, err := quoteOfPayload(response.Payload)
	if err != nil || !sameQuoteJSON(settled, proved) {
		return &Error{http.StatusBadGateway, "invalid_solana_settlement"}
	}
	state, err := w.prover.Complete(ctx, SolanaCompleteInput{Config: file.Config, State: file.State, Journal: file.Journal, Response: recovery.Response})
	if err != nil {
		return err
	}
	return w.update(func(f *solanaWalletFile) { f.State, f.Journal, f.Lease = state, nil, nil })
}

// Recover resolves any unfinished request left by an earlier run.
func (w *SolanaWallet) Recover(ctx context.Context) error {
	release, err := w.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	return w.recoverLocked(ctx)
}

// service does what the wallet owes the server right now, re-reading the state
// under the operation slot: recovery of a request without a lease record, or
// settlement of a lease whose time has come. It is a no-op otherwise.
func (w *SolanaWallet) service(ctx context.Context) error {
	release, err := w.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	file := w.snapshot()
	switch {
	case !file.hasJournal():
		return nil
	case file.Lease == nil:
		return w.recoverLocked(ctx)
	case w.unix() >= file.Lease.SettleAfter:
		_, err := w.settleLocked(ctx, false)
		return err
	}
	return nil
}

// RunSettlement settles the open lease when its time comes, until ctx ends. It
// also runs once at start so a lease from an earlier run is not forgotten.
func (w *SolanaWallet) RunSettlement(ctx context.Context, logf func(format string, args ...any)) {
	retry := time.Second
	for {
		status := w.Status()
		wait := 30 * time.Second
		if status.PendingRequest {
			if status.SettleAfter == 0 {
				wait = 0 // unresolved without a lease record: recover now
			} else if due := time.Unix(int64(status.SettleAfter), 0).Add(250 * time.Millisecond); w.now().Before(due) {
				wait = min(due.Sub(w.now()), wait)
			} else {
				wait = 0
			}
		}
		if wait == 0 {
			err := w.service(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				if logf != nil {
					logf("Solana lease settlement is not final yet (%v); retrying", err)
				}
				wait = retry
				retry = min(retry*2, 30*time.Second)
			} else {
				retry = time.Second
				wait = time.Second
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-w.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}
