package zkapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

const (
	testNullifier = "0x" + "aa00000000000000000000000000000000000000000000000000000000000001"
	testBinding   = "0x" + "bb00000000000000000000000000000000000000000000000000000000000002"
	testChainID   = "11235813213455891"
	testBase      = "http://127.0.0.1:1/zk"
	testPrice     = 15_000_000_000
)

func testHash(id string) string { return "0x" + hex.EncodeToString([]byte(id)) }

func testPin(serverURL string) config.Solana {
	pin := config.Solana{
		ServerURL: serverURL, IndexerURL: serverURL, InferenceBase: testBase, Cluster: "localnet",
		ProgramID: "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H", VaultState: "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE",
		GenesisHash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", ChainID: testChainID, ProtocolBinding: testBinding,
		StateSigningKey:     config.CurvePoint{X: "0x" + strings.Repeat("11", 32), Y: "0x" + strings.Repeat("12", 32)},
		ClearanceSigningKey: config.CurvePoint{X: "0x" + strings.Repeat("21", 32), Y: "0x" + strings.Repeat("22", 32)},
		MinLeaseCredits:     12_000_000,
	}
	pin.Normalize()
	return pin
}

// fakeProver stands in for the Rust wallet helper: it records what it is asked
// to prove and returns a distinct "proof" for every call, with a nullifier that
// is (like the real one) a function of the note state only.
type fakeProver struct {
	mu       sync.Mutex
	prepared int
	budgets  []uint64
	failNext error
}

func (p *fakeProver) Derive(context.Context, string, string, string) (SolanaDerivation, error) {
	return SolanaDerivation{ChainID: testChainID, ProtocolBinding: testBinding}, nil
}

func (p *fakeProver) Prepare(_ context.Context, in SolanaPrepareInput) (SolanaPrepared, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext != nil {
		err := p.failNext
		p.failNext = nil
		return SolanaPrepared{}, err
	}
	p.prepared++
	var cfg struct {
		Cap uint64 `json:"request_charge_cap"`
	}
	_ = json.Unmarshal(in.Config, &cfg)
	p.budgets = append(p.budgets, cfg.Cap)
	request := map[string]any{
		"client_request_id": in.ClientRequestID, "payload": in.Payload, "payload_hash": testHash(in.ClientRequestID),
		"public_inputs": map[string]any{"request_nullifier": testNullifier, "solvency_bound": cfg.Cap},
		"proof":         fmt.Sprintf("proof-%d", p.prepared),
	}
	journal := map[string]any{"exists": true, "client_request_id": in.ClientRequestID, "nullifier": testNullifier,
		"payload_hash": request["payload_hash"], "user_rerandomization": "0xsecret", "prepared_request": request}
	rawRequest, _ := json.Marshal(request)
	rawJournal, _ := json.Marshal(journal)
	return SolanaPrepared{Request: rawRequest, Journal: rawJournal}, nil
}

func (p *fakeProver) Complete(_ context.Context, in SolanaCompleteInput) (json.RawMessage, error) {
	var response struct {
		Charge string `json:"charge_applied"`
	}
	var state map[string]any
	decoder := json.NewDecoder(bytes.NewReader(in.State))
	decoder.UseNumber()
	if json.Unmarshal(in.Response, &response) != nil || decoder.Decode(&state) != nil {
		return nil, errors.New("bad input")
	}
	var charge, balance int64
	fmt.Sscan(response.Charge, &charge)
	fmt.Sscan(fmt.Sprint(state["current_balance"]), &balance)
	state["current_balance"] = balance - charge
	state["is_genesis"] = false
	return json.Marshal(state)
}

// fakeServer is serverd's native-SOL surface, with injectable behavior.
type fakeServer struct {
	t       *testing.T
	srv     *httptest.Server
	clock   atomic.Int64
	price   atomic.Int64
	walletF string
	mu      sync.Mutex

	posts         [][]byte
	quotes        int
	expires       int
	retires       int
	journalAtPost []bool
	attestation   func() map[string]any
	leasePost     func(n int, body []byte) (int, any)
	expire        func(n int, quoteExpiry int64) (int, any)
	status        func(id string) (int, any)
	nullifier     func() (int, any)
	retire        func(n int, id string) (int, any)
	settlement    func(id string) (int, any)
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t}
	f.clock.Store(1_800_000_000)
	f.price.Store(testPrice)
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	mux.HandleFunc("GET /v1/attestation", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"chain_id": json.Number(testChainID), "contract_address": testBinding,
			"state_signing_key":     map[string]string{"x": "0x" + strings.Repeat("11", 32), "y": "0x" + strings.Repeat("12", 32)},
			"clearance_signing_key": map[string]string{"x": "0x" + strings.Repeat("21", 32), "y": "0x" + strings.Repeat("22", 32)}}
		if f.attestation != nil {
			body = f.attestation()
		}
		reply(w, 200, body)
	})
	mux.HandleFunc("GET /v1/tree/snapshot", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"root": "0x01", "next_note_id": 1, "leaves": []string{"0x02"}})
	})
	mux.HandleFunc("GET /v2/billing/quote", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.quotes++
		f.mu.Unlock()
		reply(w, 200, f.quote())
	})
	mux.HandleFunc("POST /v2/openrouter/leases", func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		_, _ = body.ReadFrom(r.Body)
		f.mu.Lock()
		f.posts = append(f.posts, body.Bytes())
		n := len(f.posts)
		saved, _ := os.ReadFile(f.walletF)
		var file solanaWalletFile
		_ = json.Unmarshal(saved, &file)
		f.journalAtPost = append(f.journalAtPost, file.hasJournal())
		f.mu.Unlock()
		status, payload := f.leasePost(n, body.Bytes())
		reply(w, status, payload)
	})
	mux.HandleFunc("POST /v2/openrouter/leases/{id}/expire", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.expires++
		n := f.expires
		f.mu.Unlock()
		var request struct {
			Payload string `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		quote, _ := quoteOfPayload(request.Payload)
		var q solanaQuote
		_ = json.Unmarshal(quote, &q)
		status, payload := f.expire(n, int64(q.ExpiresAt))
		if m, ok := payload.(map[string]any); ok && m["status"] != nil && m["client_request_id"] == nil {
			m["client_request_id"] = r.PathValue("id")
			m["request_nullifier"] = testNullifier
			m["payload_hash"] = testHash(r.PathValue("id"))
		}
		reply(w, status, payload)
	})
	mux.HandleFunc("GET /v2/openrouter/leases/{id}", func(w http.ResponseWriter, r *http.Request) {
		status, payload := f.status(r.PathValue("id"))
		reply(w, status, payload)
	})
	mux.HandleFunc("POST /v2/openrouter/leases/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.retires++
		n := f.retires
		f.mu.Unlock()
		status, payload := f.retire(n, r.PathValue("id"))
		reply(w, status, payload)
	})
	mux.HandleFunc("GET /v2/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		status, payload := f.settlement(r.PathValue("id"))
		reply(w, status, payload)
	})
	mux.HandleFunc("GET /v2/nullifiers/{n}", func(w http.ResponseWriter, r *http.Request) {
		status, payload := f.nullifier()
		reply(w, status, payload)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.leasePost = func(int, []byte) (int, any) { return 500, nil }
	f.expire = func(int, int64) (int, any) { return 500, nil }
	f.status = func(string) (int, any) { return 404, nil }
	f.nullifier = func() (int, any) { return 200, map[string]any{"status": "not_found", "nullifier_status": "unknown"} }
	f.retire = func(int, string) (int, any) { return 500, nil }
	f.settlement = func(string) (int, any) {
		return 200, map[string]any{"status": "not_found", "nullifier_status": "unknown"}
	}
	return f
}

func (f *fakeServer) now() int64 { return f.clock.Load() }

func (f *fakeServer) quote() map[string]any {
	publish := f.now() - 5
	return map[string]any{"asset": "native_sol", "source": solanaSource, "credit_unit": "lamports", "base_units_per_asset": lamportsPerSOL,
		"chain_id": testChainID, "deployment_binding": testBinding, "backend": solanaBackend, "network": "localnet",
		"vault": "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE", "feed_id": config.PythSolUsdFeedID, "feed_account": config.PythSolUsdShardZeroPrice,
		"receiver_program": config.PythReceiverProgram, "price": fmt.Sprint(f.price.Load()), "exponent": -8, "confidence": "1000000",
		"publish_time": publish, "expires_at": publish + 60, "posted_slot": 77}
}

// issued is a valid 201 body for a posted request, at the quote it proved.
func (f *fakeServer) issued(body []byte, mutate func(map[string]any)) (int, any) {
	var request struct {
		ID      string `json:"client_request_id"`
		Payload string `json:"payload"`
	}
	_ = json.Unmarshal(body, &request)
	quote, _ := quoteOfPayload(request.Payload)
	var q solanaQuote
	_ = json.Unmarshal(quote, &q)
	units, _ := q.unitsForMicroUSD(2_000_000)
	lease := map[string]any{"status": "active", "client_request_id": request.ID, "api_key": "vcii_zk_unit_test_key", "openrouter_api_base": testBase + "/",
		"issued_at": f.now(), "expires_at": f.now() + 3600, "valid_for_seconds": 3600, "settle_after": f.now() + 3601,
		"spending_limit_usd": float64(q.microUSDForUnits(units)) / 1e6, "key_source": "openrouter", "billing_quote": json.RawMessage(quote)}
	if mutate != nil {
		mutate(lease)
	}
	return 201, lease
}

type fixture struct {
	t      *testing.T
	dir    string
	server *fakeServer
	prover *fakeProver
	pin    config.Solana
	wallet *SolanaWallet
	slept  []time.Duration
}

func newFixture(t *testing.T, balance int64) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: filepath.Join(t.TempDir(), "cfg"), server: newFakeServer(t), prover: &fakeProver{}}
	if err := os.MkdirAll(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.pin = testPin(f.server.srv.URL)
	f.server.walletF = solanaWalletPath(f.dir, f.pin)
	export := fmt.Sprintf(`{"config":{"protocol_version":2,"ledger_backend":%q,"chain_id":%q,"contract_address":%q,"request_charge_cap":12000000,"policy_charge_cap":0,"policy_enabled":false},
		"state":{"note_id":0,"chain_id":%q,"contract_address":%q,"current_balance":%d,"secret_s":"0xsecret"},"journal":null}`,
		solanaBackend, testChainID, testBinding, testChainID, testBinding, balance)
	if err := ImportSolanaWallet(f.dir, f.pin, []byte(export)); err != nil {
		t.Fatal(err)
	}
	f.open()
	return f
}

// open (re)loads the wallet from disk, as a restarted daemon would.
func (f *fixture) open() {
	wallet, err := OpenSolanaWallet(f.dir, f.pin, f.server.srv.Client(), f.prover)
	if err != nil {
		f.t.Fatal(err)
	}
	wallet.now = func() time.Time { return time.Unix(f.server.now(), 0) }
	wallet.sleep = func(_ context.Context, d time.Duration) error {
		f.slept = append(f.slept, d)
		f.server.clock.Add(int64(d / time.Second))
		return nil
	}
	f.wallet = wallet
}

func (f *fixture) file() solanaWalletFile {
	raw, err := os.ReadFile(f.server.walletF)
	if err != nil {
		f.t.Fatal(err)
	}
	var file solanaWalletFile
	if err := json.Unmarshal(raw, &file); err != nil {
		f.t.Fatal(err)
	}
	return file
}

func errorCode(err error) string {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Code
	}
	return fmt.Sprint(err)
}

func TestExportLeaseHappyPathPersistsJournalBeforeSendingAndNeverStoresTheKey(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	lease, err := f.wallet.ExportLease(context.Background(), 2_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if lease.APIKey != "vcii_zk_unit_test_key" || lease.LimitMicroUSD != 2_000_000 || lease.ExpiresAt != uint64(f.server.now()+3600) || lease.BaseURL != testBase+"/" {
		t.Fatalf("lease=%+v", lease)
	}
	// 2 USD at (150.00 - 0.01) USD/SOL rounded up to whole lamports.
	if len(f.prover.budgets) != 1 || f.prover.budgets[0] != 13_334_223 {
		t.Fatalf("budgets=%v", f.prover.budgets)
	}
	if len(f.server.journalAtPost) != 1 || !f.server.journalAtPost[0] {
		t.Fatal("the request journal was not durable before the proof was sent")
	}
	raw, _ := os.ReadFile(f.server.walletF)
	if bytes.Contains(raw, []byte("vcii_zk_unit_test_key")) {
		t.Fatal("the exported key was written to the wallet file")
	}
	info, _ := os.Stat(f.server.walletF)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("wallet file mode %v", info.Mode().Perm())
	}
	file := f.file()
	if !file.hasJournal() || file.Lease == nil || file.Lease.SettleAfter != uint64(f.server.now()+3601) {
		t.Fatalf("saved lease %+v", file.Lease)
	}
	// A second export fails fast while the first key is open, and proves nothing.
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); errorCode(err) != "lease_pending" || f.prover.prepared != 1 {
		t.Fatalf("err=%v prepared=%d", err, f.prover.prepared)
	}
}

func TestExportLeaseRetriesNativeQuoteStaleWithAFreshProofEachTime(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(n int, body []byte) (int, any) {
		if n < 3 {
			return 409, map[string]any{"status": "error", "error_code": "native_quote_stale", "retriable": true}
		}
		return f.server.issued(body, nil)
	}
	f.server.expire = func(int, int64) (int, any) { return 200, map[string]any{"status": "superseded_unaccepted"} }
	lease, err := f.wallet.ExportLease(context.Background(), 2_000_000)
	if err != nil || lease.APIKey == "" {
		t.Fatalf("lease=%+v err=%v", lease, err)
	}
	if f.prover.prepared != 3 || len(f.server.posts) != 3 || f.server.expires != 2 || f.server.quotes != 3 {
		t.Fatalf("prepared=%d posts=%d expires=%d quotes=%d", f.prover.prepared, len(f.server.posts), f.server.expires, f.server.quotes)
	}
	seen := map[string]bool{}
	for _, body := range f.server.posts {
		if seen[string(body)] {
			t.Fatal("the same proof was sent twice")
		}
		seen[string(body)] = true
	}
	for i, durable := range f.server.journalAtPost {
		if !durable {
			t.Fatalf("attempt %d was sent without a durable journal", i+1)
		}
	}
	if !f.file().hasJournal() {
		t.Fatal("the accepted request's journal must remain for settlement")
	}
}

func TestExportLeaseGivesUpAfterFourStaleRefusalsAndLeavesNothingPending(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(int, []byte) (int, any) {
		return 409, map[string]any{"status": "error", "error_code": "native_quote_stale", "retriable": true}
	}
	f.server.expire = func(int, int64) (int, any) { return 200, map[string]any{"status": "superseded_unaccepted"} }
	_, err := f.wallet.ExportLease(context.Background(), 2_000_000)
	if errorCode(err) != "native_quote_stale" {
		t.Fatalf("err=%v", err)
	}
	if f.prover.prepared != MaxLeaseQuoteAttempts || len(f.server.posts) != MaxLeaseQuoteAttempts || f.server.expires != MaxLeaseQuoteAttempts {
		t.Fatalf("prepared=%d posts=%d expires=%d", f.prover.prepared, len(f.server.posts), f.server.expires)
	}
	if f.file().hasJournal() || f.file().Lease != nil {
		t.Fatal("a refused request left a journal behind")
	}
	// A later attempt starts fresh.
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
}

func TestStaleRefusalIsRetriedOnlyAfterNonAcceptanceIsConfirmed(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(int, []byte) (int, any) {
		return 409, map[string]any{"status": "error", "error_code": "native_quote_stale", "retriable": true}
	}
	// The price recovered, so the server cannot say the request is unaccepted
	// until its quote expires: lease_pending, then expired_unaccepted.
	f.server.expire = func(_ int, expiry int64) (int, any) {
		if f.server.now() <= expiry {
			return 409, map[string]any{"status": "error", "error_code": "lease_pending"}
		}
		return 200, map[string]any{"status": "expired_unaccepted"}
	}
	f.server.leasePost = func(n int, body []byte) (int, any) {
		if n == 1 {
			return 409, map[string]any{"status": "error", "error_code": "native_quote_stale", "retriable": true}
		}
		return f.server.issued(body, nil)
	}
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	if len(f.slept) == 0 || f.prover.prepared != 2 {
		t.Fatalf("slept=%v prepared=%d", f.slept, f.prover.prepared)
	}
}

func TestUnconfirmedStaleKeepsTheJournalAndBlocksNewProofs(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(int, []byte) (int, any) {
		return 409, map[string]any{"status": "error", "error_code": "native_quote_stale", "retriable": true}
	}
	f.server.expire = func(int, int64) (int, any) { return 500, nil }
	_, err := f.wallet.ExportLease(context.Background(), 2_000_000)
	if errorCode(err) != "native_quote_stale_unconfirmed" || f.prover.prepared != 1 || !f.file().hasJournal() {
		t.Fatalf("err=%v prepared=%d journal=%v", err, f.prover.prepared, f.file().hasJournal())
	}
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); errorCode(err) != "lease_pending" || f.prover.prepared != 1 {
		t.Fatalf("a new proof was made while an earlier request's outcome was unknown: %v", err)
	}
}

func TestUnknownOutcomeIsRecoveredBeforeAnyNewProof(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(n int, body []byte) (int, any) {
		if n == 1 {
			return 500, nil // the answer is lost: the request may or may not have been accepted
		}
		return f.server.issued(body, nil)
	}
	_, err := f.wallet.ExportLease(context.Background(), 2_000_000)
	if errorCode(err) != "lease_outcome_unknown" || !f.file().hasJournal() {
		t.Fatalf("err=%v", err)
	}
	// Restart: the journal survives; the server never saw the request and, once
	// the quote can no longer be accepted, says so.
	f.open()
	f.server.expire = func(_ int, expiry int64) (int, any) {
		if f.server.now() <= expiry {
			return 409, map[string]any{"status": "error", "error_code": "lease_pending"}
		}
		return 200, map[string]any{"status": "expired_unaccepted"}
	}
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	if f.prover.prepared != 2 || len(f.server.posts) != 2 || bytes.Equal(f.server.posts[0], f.server.posts[1]) {
		t.Fatalf("prepared=%d posts=%d", f.prover.prepared, len(f.server.posts))
	}
}

func settlementFor(f *fixture, charge string) func(string) (int, any) {
	return func(id string) (int, any) {
		file := f.file()
		var journal struct {
			Prepared json.RawMessage `json:"prepared_request"`
		}
		_ = json.Unmarshal(file.Journal, &journal)
		quote, _ := quoteOfRequest(journal.Prepared)
		payload, _ := json.Marshal(map[string]any{"usage_usd": 1.5, "billing_quote": json.RawMessage(quote)})
		return 200, map[string]any{"status": "ok", "nullifier_status": "finalized",
			"request_response": map[string]any{"client_request_id": id, "charge_applied": charge, "response_payload": string(payload)}}
	}
}

func TestSettlementWaitsForItsTimeThenInstallsTheReceipt(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	f.server.retire = func(int, string) (int, any) { return 200, map[string]any{"status": "finalized"} }
	f.server.status = func(string) (int, any) { return 200, map[string]any{"status": "active"} }
	f.server.settlement = settlementFor(f, "10000000")
	if _, err := f.wallet.Settle(context.Background(), false); errorCode(err) != "lease_pending" || f.server.retires != 0 {
		t.Fatalf("settled before its time: %v retires=%d", err, f.server.retires)
	}
	f.server.clock.Add(3602)
	result, err := f.wallet.Settle(context.Background(), false)
	if err != nil || !result.Settled || result.Balance != "990000000" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if file := f.file(); file.hasJournal() || file.Lease != nil {
		t.Fatal("journal or lease survived settlement")
	}
	// The wallet is free again.
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
}

func TestForcedSettlementRetriesAnExplicitlyRetriableRefusal(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	f.server.retire = func(n int, _ string) (int, any) {
		if n < 3 {
			return 409, map[string]any{"status": "error", "error_code": "lease_settlement_pending", "retriable": true, "retry_after_seconds": 3}
		}
		return 200, map[string]any{"status": "finalized"}
	}
	f.server.settlement = settlementFor(f, "5")
	result, err := f.wallet.Settle(context.Background(), true)
	if err != nil || !result.Settled || f.server.retires != 3 || len(f.slept) != 2 || f.slept[0] < 3*time.Second {
		t.Fatalf("result=%+v err=%v retires=%d slept=%v", result, err, f.server.retires, f.slept)
	}
}

func TestSettlementRejectsAReceiptThatChangedTheQuote(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	f.server.retire = func(int, string) (int, any) { return 200, map[string]any{"status": "finalized"} }
	f.server.settlement = func(id string) (int, any) {
		other := f.server.quote()
		other["price"] = "14000000000"
		payload, _ := json.Marshal(map[string]any{"billing_quote": other})
		return 200, map[string]any{"request_response": map[string]any{"client_request_id": id, "charge_applied": "1", "response_payload": string(payload)}}
	}
	if _, err := f.wallet.Settle(context.Background(), true); errorCode(err) != "invalid_solana_settlement" || !f.file().hasJournal() {
		t.Fatalf("err=%v", err)
	}
}

func TestRestartKeepsAnOpenLeaseAndRetiresALostKey(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	f.server.status = func(string) (int, any) { return 200, map[string]any{"status": "active"} }
	f.server.retire = func(int, string) (int, any) { return 200, map[string]any{"status": "finalized"} }
	f.server.settlement = settlementFor(f, "7")
	// Restart while the exported key is still valid: nothing is retired.
	f.open()
	if err := f.wallet.Recover(context.Background()); errorCode(err) != "lease_pending" || f.server.retires != 0 {
		t.Fatalf("err=%v retires=%d", err, f.server.retires)
	}
	// Crash between journaling and recording the lease: the key was never shown
	// to anyone, so recovery retires it at once.
	file := f.file()
	file.Lease = nil
	if err := file.save(f.server.walletF); err != nil {
		t.Fatal(err)
	}
	f.open()
	if err := f.wallet.Recover(context.Background()); err != nil || f.server.retires != 1 || f.file().hasJournal() {
		t.Fatalf("err=%v retires=%d", err, f.server.retires)
	}
}

func TestInvalidLeaseIsRetiredAndNeverReturned(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"wrong cap":  func(l map[string]any) { l["spending_limit_usd"] = 9.5 },
		"wrong base": func(l map[string]any) { l["openrouter_api_base"] = "https://evil.example/api" },
		"other quote": func(l map[string]any) {
			quote := map[string]any{}
			_ = json.Unmarshal(l["billing_quote"].(json.RawMessage), &quote)
			quote["price"] = "14999999999"
			l["billing_quote"] = quote
		},
		"oa key":   func(l map[string]any) { l["key_source"] = "oa_org" },
		"space":    func(l map[string]any) { l["api_key"] = "a b" },
		"inactive": func(l map[string]any) { l["status"] = "finalized" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1_000_000_000)
			f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, mutate) }
			f.server.retire = func(int, string) (int, any) { return 200, map[string]any{"status": "finalized"} }
			f.server.settlement = settlementFor(f, "1")
			lease, err := f.wallet.ExportLease(context.Background(), 2_000_000)
			if errorCode(err) != "invalid_solana_lease" || lease.APIKey != "" || f.server.retires != 1 {
				t.Fatalf("lease=%+v err=%v retires=%d", lease, err, f.server.retires)
			}
		})
	}
}

func TestExportLeaseChecksBudgetAndDeploymentBeforeProving(t *testing.T) {
	f := newFixture(t, 5_000_000) // 0.005 SOL
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); errorCode(err) != "insufficient_private_balance" {
		t.Fatalf("err=%v", err)
	}
	if _, err := f.wallet.ExportLease(context.Background(), 1_000_000); errorCode(err) != "lease_below_deployment_minimum" {
		t.Fatalf("err=%v", err)
	}
	f = newFixture(t, 1_000_000_000)
	f.server.attestation = func() map[string]any {
		return map[string]any{"chain_id": json.Number(testChainID), "contract_address": testBinding,
			"state_signing_key":     map[string]string{"x": "0x" + strings.Repeat("99", 32), "y": "0x" + strings.Repeat("12", 32)},
			"clearance_signing_key": map[string]string{"x": "0x" + strings.Repeat("21", 32), "y": "0x" + strings.Repeat("22", 32)}}
	}
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); errorCode(err) != "solana_deployment_mismatch" {
		t.Fatalf("err=%v", err)
	}
	for _, limit := range []uint64{0, MaxExportLimitMicroUSD + 1} {
		if _, err := f.wallet.ExportLease(context.Background(), limit); err == nil {
			t.Fatal("bad limit accepted")
		}
	}
	if f.prover.prepared != 0 {
		t.Fatal("a proof was made for a refused lease")
	}
}

func TestQuoteValidationAndConversion(t *testing.T) {
	pin := testPin("http://127.0.0.1:1")
	fake := newFakeServer(t)
	now := uint64(fake.now())
	good, _ := json.Marshal(fake.quote())
	quote, err := parseSolanaQuote(good, &pin, now)
	if err != nil {
		t.Fatal(err)
	}
	if units, _ := quote.unitsForMicroUSD(2_000_000); units != 13_334_223 || quote.microUSDForUnits(units) != 2_000_000 {
		t.Fatalf("units=%d usd=%d", units, quote.microUSDForUnits(units))
	}
	for name, mutate := range map[string]func(map[string]any){
		"vault":      func(q map[string]any) { q["vault"] = "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H" },
		"chain":      func(q map[string]any) { q["chain_id"] = "1" },
		"binding":    func(q map[string]any) { q["deployment_binding"] = "0x" + strings.Repeat("00", 32) },
		"cluster":    func(q map[string]any) { q["network"] = "mainnet-beta" },
		"feed":       func(q map[string]any) { q["feed_id"] = "0x" + strings.Repeat("00", 32) },
		"account":    func(q map[string]any) { q["feed_account"] = "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H" },
		"source":     func(q map[string]any) { q["source"] = "pyth_receiver" },
		"expired":    func(q map[string]any) { q["publish_time"], q["expires_at"] = int64(now-90), int64(now-30) },
		"future":     func(q map[string]any) { q["publish_time"], q["expires_at"] = int64(now+30), int64(now+90) },
		"lifetime":   func(q map[string]any) { q["expires_at"] = int64(now + 600) },
		"confidence": func(q map[string]any) { q["confidence"] = "999999999" },
		"zero":       func(q map[string]any) { q["price"], q["confidence"] = "0", "0" },
		"unit":       func(q map[string]any) { q["credit_unit"] = "gwei" },
		"extra":      func(q map[string]any) { q["surprise"] = true },
		"float":      func(q map[string]any) { q["price"] = "1.5e10" },
	} {
		q := fake.quote()
		mutate(q)
		raw, _ := json.Marshal(q)
		if _, err := parseSolanaQuote(raw, &pin, now); err == nil {
			t.Errorf("%s: invalid quote accepted", name)
		}
	}
}

func TestImportAndOpenBindTheWalletToThePinnedDeployment(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	if err := ImportSolanaWallet(f.dir, f.pin, []byte(`{"config":{},"state":{}}`)); err == nil {
		t.Fatal("import overwrote or accepted a bad wallet")
	}
	other := f.pin
	other.ChainID = "7"
	if _, err := OpenSolanaWallet(f.dir, other, nil, f.prover); err == nil {
		t.Fatal("wallet opened under another deployment")
	}
	if err := os.Chmod(f.server.walletF, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSolanaWallet(f.dir, f.pin, nil, f.prover); err == nil {
		t.Fatal("readable wallet file accepted")
	}
	pending := `{"config":{},"state":{"a":1},"journal":{"exists":true}}`
	if err := ImportSolanaWallet(t.TempDir(), f.pin, []byte(pending)); err == nil {
		t.Fatal("wallet with a pending request imported")
	}
}

func TestExecProverSpeaksTheHelperProtocolAndDropsHelperErrors(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "helper.sh")
	// A stand-in helper: replies per command, echoing the request id.
	body := `#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
  case "$line" in
    *'"command":"derive_deployment"'*) printf '{"id":%s,"ok":true,"result":{"chain_id":"42","protocol_binding":"0x01"}}\n' "$id" ;;
    *'"command":"load_wallet"'*) printf '{"id":%s,"ok":true,"result":{}}\n' "$id" ;;
    *'"command":"tree_path"'*) printf '{"id":%s,"ok":true,"result":{"active_root":"0x01","siblings":["0x02"]}}\n' "$id" ;;
    *'"command":"prepare_request"'*) printf '{"id":%s,"ok":true,"result":{"request":{"r":1},"journal":{"j":1}}}\n' "$id" ;;
    *) printf '{"id":%s,"ok":false,"error":"secret detail 0xdeadbeef"}\n' "$id" ;;
  esac
done
`
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	prover := ExecSolanaProver{Binary: script, SetupDir: dir}
	derived, err := prover.Derive(context.Background(), "p", "v", "g")
	if err != nil || derived.ChainID != "42" {
		t.Fatalf("derived=%+v err=%v", derived, err)
	}
	prepared, err := prover.Prepare(context.Background(), SolanaPrepareInput{Config: json.RawMessage(`{}`), State: json.RawMessage(`{}`), Snapshot: json.RawMessage(`{}`), Payload: "p", ClientRequestID: "id"})
	if err != nil || string(prepared.Request) != `{"r":1}` || string(prepared.Journal) != `{"j":1}` {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	_, err = prover.Complete(context.Background(), SolanaCompleteInput{Config: json.RawMessage(`{}`), State: json.RawMessage(`{}`), Journal: json.RawMessage(`{}`), Response: json.RawMessage(`{}`)})
	if err == nil || strings.Contains(err.Error(), "deadbeef") {
		t.Fatalf("helper detail leaked or error missing: %v", err)
	}
}

func TestRunSettlementSettlesADueLeaseInTheBackgroundAndStopsWithItsContext(t *testing.T) {
	f := newFixture(t, 1_000_000_000)
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	f.server.status = func(string) (int, any) { return 200, map[string]any{"status": "active"} }
	f.server.retire = func(int, string) (int, any) { return 200, map[string]any{"status": "finalized"} }
	f.server.settlement = settlementFor(f, "10000000")
	f.server.clock.Add(3602) // the lease is now due
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.wallet.RunSettlement(ctx, nil)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for f.wallet.Status().PendingRequest && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if f.wallet.Status().PendingRequest || f.wallet.Status().Balance != "990000000" {
		t.Fatalf("status=%+v", f.wallet.Status())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSettlement ignored its context")
	}
}
