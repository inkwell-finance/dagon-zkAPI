package zkapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/solanatest"
)

const (
	testPayer       = config.PythReceiverProgram // any valid 32-byte account stands in for the funding keypair's public key
	testDestination = config.PythSolUsdShardZeroPrice
	testSecret      = "0xdeadbeefsecret"
)

// simOp is one staged operation the fake helper prepared.
type simOp struct {
	kind       string // deposit, close or cancel
	noteID     uint32
	commitment string
	amount     uint64
	nullifier  string
	cancels    string
	lastValid  uint64
	landed     bool
	signed     bool
}

// fakeFunder is the wallet helper plus the vault, simulated: it prepares, signs
// and "lands" operations on an in-memory chain, so the wallet's journaling and
// recovery can be tested against crashes, expiry and racing depositors.
type fakeFunder struct {
	mu         sync.Mutex
	t          *testing.T
	walletFile string // read at helper calls to assert what was durable by then

	nextNote   uint32
	notes      map[uint32]SolanaNoteInfo
	used       map[string]bool
	paid       map[string]uint64 // lamports paid out by closes, by destination
	ops        map[string]*simOp
	height     uint64
	lastValid  uint64
	counter    int
	signCalls  int
	submits    int
	cancelled  []string
	prepares   int
	proofs     int
	secrets    int
	failSubmit []error // consumed one per SubmitSigned call
	staleRoots int     // PrepareWithdrawal answers stale_root this many times
	stolenNote bool    // another depositor takes the next deposit's note ID just before it executes

	journalAtPrepare []bool // wallet file held the deposit secret when the helper was asked to prepare
}

func newFakeFunder(t *testing.T, walletFile string) *fakeFunder {
	return &fakeFunder{t: t, walletFile: walletFile, notes: map[uint32]SolanaNoteInfo{}, used: map[string]bool{}, paid: map[string]uint64{},
		ops: map[string]*simOp{}, height: 1000, lastValid: 1150}
}

func (f *fakeFunder) WalletConfig(_ context.Context, pin config.Solana) (json.RawMessage, error) {
	return json.RawMessage(fmt.Sprintf(`{"protocol_version":2,"ledger_backend":%q,"chain_id":%q,"contract_address":%q,"request_charge_cap":%d,"policy_charge_cap":0,"policy_enabled":false}`,
		solanaBackend, pin.ChainID, pin.ProtocolBinding, pin.MinLeaseCredits)), nil
}

func (f *fakeFunder) KeypairPubkey(_ context.Context, path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", &Error{502, "solana_prover_failed"}
	}
	return strings.TrimSpace(string(raw)), nil
}

func (f *fakeFunder) DepositParams(context.Context) (SolanaDepositParams, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets++
	return SolanaDepositParams{Secret: fmt.Sprintf("%s%d", testSecret, f.secrets), Commitment: fmt.Sprintf("0xc0%d", f.secrets)}, nil
}

func (f *fakeFunder) durable() solanaWalletFile {
	raw, err := os.ReadFile(f.walletFile)
	if err != nil {
		f.t.Fatal(err)
	}
	var file solanaWalletFile
	if err := json.Unmarshal(raw, &file); err != nil {
		f.t.Fatal(err)
	}
	return file
}

func (f *fakeFunder) newOp(op *simOp) (string, json.RawMessage) {
	f.counter++
	id := fmt.Sprintf("op%02d", f.counter)
	op.lastValid = f.lastValid
	f.ops[id] = op
	raw, _ := json.Marshal(map[string]any{"operation_id": id, "transactions": []map[string]any{
		{"message_b64": "init-" + id, "last_valid_height": f.lastValid}, {"message_b64": "exec-" + id, "last_valid_height": f.lastValid}}})
	return id, raw
}

func (f *fakeFunder) PrepareDeposit(_ context.Context, payer, commitment string, amount uint64) (uint32, json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file := f.durable()
	f.journalAtPrepare = append(f.journalAtPrepare, file.Deposit != nil && strings.HasPrefix(file.Deposit.Secret, testSecret) && file.Deposit.Payer == payer)
	f.prepares++
	id := f.nextNote
	_, op := f.newOp(&simOp{kind: "deposit", noteID: id, commitment: commitment, amount: amount})
	return id, op, nil
}

func (f *fakeFunder) ConfirmDeposit(_ context.Context, walletConfig json.RawMessage, secret string, noteID uint32, amount, expiry uint64) (json.RawMessage, error) {
	if !strings.HasPrefix(secret, testSecret) {
		f.t.Errorf("confirm with a foreign secret %q", secret)
	}
	return json.RawMessage(fmt.Sprintf(`{"note_id":%d,"chain_id":%q,"contract_address":%q,"current_balance":%d,"deposit_amount":%d,"expiry_ts":%d,"secret_s":%q}`,
		noteID, testChainID, testBinding, amount, amount, expiry, secret)), nil
}

func (f *fakeFunder) WithdrawalNullifier(_ context.Context, _, state json.RawMessage) (string, error) {
	var note struct {
		NoteID uint32 `json:"note_id"`
	}
	_ = json.Unmarshal(state, &note)
	return fmt.Sprintf("0xaa%02x", note.NoteID), nil
}

func (f *fakeFunder) ProveWithdrawal(_ context.Context, _, _ json.RawMessage, in SolanaWithdrawInput) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proofs++
	if !strings.Contains(string(in.Clearance), `"status":"ok"`) {
		f.t.Errorf("proving without the server's clearance: %s", in.Clearance)
	}
	return json.RawMessage(fmt.Sprintf(`{"mode":"mutual","proof":%d,"destination":%q}`, f.proofs, in.Destination)), nil
}

func (f *fakeFunder) PrepareWithdrawal(_ context.Context, payer, destination string, plan json.RawMessage) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.staleRoots > 0 {
		f.staleRoots--
		return nil, &helperError{helperStaleRoot}
	}
	file := f.durable()
	if file.Withdrawal == nil || file.Withdrawal.Plan == nil {
		f.t.Error("the close was prepared before its plan was durable")
	}
	_, op := f.newOp(&simOp{kind: "close", noteID: file.Withdrawal.NoteID, nullifier: file.Withdrawal.Nullifier, amount: file.Withdrawal.Lamports, commitment: destination})
	return op, nil
}

func (f *fakeFunder) PrepareCancel(_ context.Context, payer, operationID string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, op := f.newOp(&simOp{kind: "cancel", cancels: operationID})
	return op, nil
}

func (f *fakeFunder) SignOperation(_ context.Context, keypairPath string, operation json.RawMessage) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signCalls++
	var parsed struct {
		ID           string `json:"operation_id"`
		Transactions []struct {
			Last uint64 `json:"last_valid_height"`
		} `json:"transactions"`
	}
	_ = json.Unmarshal(operation, &parsed)
	f.ops[parsed.ID].signed = true
	var txs []map[string]any
	for i, tx := range parsed.Transactions {
		txs = append(txs, map[string]any{"transaction_b64": "tx", "signature": fmt.Sprintf("sig-%s-%d", parsed.ID, i), "last_valid_height": tx.Last})
	}
	return json.Marshal(map[string]any{"operation_id": parsed.ID, "transactions": txs})
}

func (f *fakeFunder) opOf(signed json.RawMessage) (*simOp, string) {
	var parsed struct {
		ID string `json:"operation_id"`
	}
	_ = json.Unmarshal(signed, &parsed)
	return f.ops[parsed.ID], parsed.ID
}

func (f *fakeFunder) SubmitSigned(_ context.Context, signed json.RawMessage, finalize bool) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submits++
	if len(f.failSubmit) > 0 {
		err := f.failSubmit[0]
		f.failSubmit = f.failSubmit[1:]
		if err != nil {
			return nil, err
		}
	}
	op, id := f.opOf(signed)
	if !op.signed {
		f.t.Errorf("submitted an unsigned operation %s", id)
	}
	if f.height > op.lastValid && !op.landed {
		return nil, &helperError{helperBlockhash}
	}
	if op.landed {
		return []string{"sig-" + id}, nil
	}
	switch op.kind {
	case "deposit":
		if existing, taken := f.notes[op.noteID]; (taken && existing.Exists) || f.stolenNote {
			if f.stolenNote {
				// Another depositor's transaction took this note ID first.
				f.stolenNote = false
				f.notes[op.noteID] = SolanaNoteInfo{Exists: true, Commitment: "0xsomeoneelse", Amount: 5, Expiry: 1, Active: true}
				f.nextNote = op.noteID + 1
			}
			return nil, &helperError{helperTransactionBad}
		}
		f.notes[op.noteID] = SolanaNoteInfo{Exists: true, Commitment: op.commitment, Amount: op.amount, Expiry: 1_900_000_000, Active: true}
		f.nextNote = op.noteID + 1
	case "close":
		f.used[op.nullifier] = true
		delete(f.notes, op.noteID)
		f.paid[op.commitment] += op.amount
	case "cancel":
		f.cancelled = append(f.cancelled, op.cancels)
	}
	op.landed = true
	return []string{"sig-" + id}, nil
}

// landOperation simulates a transaction that reached the chain while the client was down.
func (f *fakeFunder) landOperation(signed json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	op, _ := f.opOf(signed)
	switch op.kind {
	case "deposit":
		f.notes[op.noteID] = SolanaNoteInfo{Exists: true, Commitment: op.commitment, Amount: op.amount, Expiry: 1_900_000_000, Active: true}
		f.nextNote = op.noteID + 1
	case "close":
		f.used[op.nullifier] = true
		delete(f.notes, op.noteID)
		f.paid[op.commitment] += op.amount
	}
	op.landed = true
}

func (f *fakeFunder) SignedStatus(_ context.Context, signed json.RawMessage) (SolanaSignedStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	op, id := f.opOf(signed)
	status := SolanaSignedStatus{}
	for i := 0; i < 2; i++ {
		progress := "unknown"
		if op.landed {
			progress = "finalized"
		}
		status.Transactions = append(status.Transactions, SolanaTxState{Signature: fmt.Sprintf("sig-%s-%d", id, i), Progress: progress})
	}
	status.Expired = !op.landed && f.height > op.lastValid
	return status, nil
}

func (f *fakeFunder) NoteStatus(_ context.Context, noteID uint32) (SolanaNoteInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notes[noteID], nil
}

func (f *fakeFunder) NullifierUsed(_ context.Context, nullifier string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.used[nullifier], nil
}

type fundingFixture struct {
	t      *testing.T
	dir    string
	pin    config.Solana
	server *fakeServer
	chain  *solanatest.Chain
	funder *fakeFunder
	wallet *SolanaWallet
	payer  string // keypair file of the funding account
	slept  []time.Duration
}

// newFundingFixture builds a wallet with no note (a profile that has never been funded).
func newFundingFixture(t *testing.T) *fundingFixture {
	t.Helper()
	f := &fundingFixture{t: t, dir: filepath.Join(t.TempDir(), "cfg"), server: newFakeServer(t)}
	if err := os.MkdirAll(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.chain = solanatest.New(t, testPin("").GenesisHash)
	f.pin = testPin(f.server.srv.URL)
	f.pin.RPCURL = f.chain.Server.URL
	f.chain.Install(f.pin)
	f.chain.Balances[testPayer] = 5_000_000_000
	f.server.walletF = solanaWalletPath(f.dir, f.pin)
	f.funder = newFakeFunder(t, f.server.walletF)
	f.payer = filepath.Join(t.TempDir(), "payer.json")
	if err := os.WriteFile(f.payer, []byte(testPayer), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitSolanaWallet(context.Background(), f.dir, f.pin, f.funder); err != nil {
		t.Fatal(err)
	}
	f.open()
	return f
}

// open (re)loads the wallet from disk, as a restarted process would.
func (f *fundingFixture) open() {
	wallet, err := OpenSolanaWallet(f.dir, f.pin, f.server.srv.Client(), &fakeProver{})
	if err != nil {
		f.t.Fatal(err)
	}
	wallet.SetFunder(f.funder)
	wallet.now = func() time.Time { return time.Unix(f.server.now(), 0) }
	wallet.sleep = func(_ context.Context, d time.Duration) error {
		f.slept = append(f.slept, d)
		f.server.clock.Add(int64(d / time.Second))
		return nil
	}
	f.wallet = wallet
}

func (f *fundingFixture) file() solanaWalletFile {
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

func (f *fundingFixture) deposit(lamports uint64) (FundingResult, error) {
	return f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: f.payer, Lamports: lamports})
}

func (f *fundingFixture) funded(lamports uint64) {
	f.t.Helper()
	if _, err := f.deposit(lamports); err != nil {
		f.t.Fatal(err)
	}
}

func fundingCode(err error) string {
	var failure *FundingError
	if errors.As(err, &failure) {
		return failure.Code
	}
	return errorCode(err)
}

func TestInitCreatesAnEmptyWalletThatCannotLease(t *testing.T) {
	f := newFundingFixture(t)
	status := f.wallet.Status()
	if status.HasNote || status.PendingRequest || status.PendingDeposit {
		t.Fatalf("a fresh wallet must be empty: %+v", status)
	}
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); fundingCode(err) != "no_funded_note" {
		t.Fatalf("lease from an empty wallet: %v", err)
	}
	if err := InitSolanaWallet(context.Background(), f.dir, f.pin, f.funder); err == nil {
		t.Fatal("init replaced an existing wallet")
	}
	info, err := os.Stat(f.server.walletF)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("wallet file mode: %v %v", info, err)
	}
}

func TestDepositJournalsTheSecretBeforeTheChainIsTouchedThenInstallsTheNote(t *testing.T) {
	f := newFundingFixture(t)
	result, err := f.deposit(1_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "deposit" || result.Lamports != 1_000_000_000 || result.Balance != "1000000000" || result.Signature == "" {
		t.Fatalf("result: %+v", result)
	}
	if len(f.funder.journalAtPrepare) != 1 || !f.funder.journalAtPrepare[0] {
		t.Fatalf("the note secret was not durable before the deposit was prepared: %v", f.funder.journalAtPrepare)
	}
	file := f.file()
	if file.Deposit != nil || file.noNote() || len(file.History) != 1 || file.History[0].Kind != "deposit" || file.History[0].Signature != result.Signature {
		t.Fatalf("durable state after a deposit: %+v", file)
	}
	if file.Keypair != f.payer {
		t.Fatalf("the funding keypair path is remembered for withdrawals: %q", file.Keypair)
	}
	if strings.Contains(fmt.Sprint(file.History), testSecret) {
		t.Fatal("the history must not carry the note secret")
	}
	status := f.wallet.Status()
	if !status.HasNote || status.Balance != "1000000000" || status.PendingDeposit {
		t.Fatalf("status: %+v", status)
	}
	// A funded note refuses a second deposit.
	if _, err := f.deposit(1); fundingCode(err) != "note_exists" {
		t.Fatalf("second deposit: %v", err)
	}
}

func TestDepositVerifiesTheChainFirstAndTouchesNothingOnMismatch(t *testing.T) {
	f := newFundingFixture(t)
	f.chain.Lock()
	f.chain.Accounts[solanatest.ProgramDataAddress(f.pin)] = solanatest.Account{Owner: solanatest.UpgradeableLoader, Data: solanatest.ProgramDataAccount(true)}
	f.chain.Unlock()
	_, err := f.deposit(1_000_000_000)
	if !errors.As(err, new(*ChainMismatchError)) {
		t.Fatalf("deposit into an upgradeable program: %v", err)
	}
	if f.file().Deposit != nil || f.funder.secrets != 0 || f.funder.prepares != 0 {
		t.Fatal("a refused deposit must not generate a secret, journal anything or prepare a transaction")
	}
}

func TestDepositRefusesBadRequestsBeforeAnySecretExists(t *testing.T) {
	f := newFundingFixture(t)
	for name, test := range map[string]struct {
		request DepositRequest
		code    string
	}{
		"zero":          {DepositRequest{KeypairPath: f.payer}, "invalid_amount"},
		"no keypair":    {DepositRequest{Lamports: 1_000_000_000}, "keypair_required"},
		"too much":      {DepositRequest{KeypairPath: f.payer, Lamports: 5_000_000_000}, "insufficient_funds"},
		"fees headroom": {DepositRequest{KeypairPath: f.payer, Lamports: 5_000_000_000 - feeHeadroomLamports + 1}, "insufficient_funds"},
	} {
		if _, err := f.wallet.Deposit(context.Background(), test.request); fundingCode(err) != test.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if f.funder.secrets != 0 || f.file().Deposit != nil {
		t.Fatal("a refused request left a secret behind")
	}
	if _, err := f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: filepath.Join(t.TempDir(), "missing.json"), Lamports: 1_000_000_000}); err == nil {
		t.Fatal("a missing keypair file was accepted")
	}
	// Exactly the headroom is enough.
	if _, err := f.deposit(5_000_000_000 - feeHeadroomLamports); err != nil {
		t.Fatalf("a deposit leaving exactly the fee headroom: %v", err)
	}
}

func TestDepositWhoseTransactionsMayHaveLandedIsRecoveredFromTheChainWithoutAKeypair(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("connection reset")}
	_, err := f.deposit(1_000_000_000)
	if fundingCode(err) != "deposit_outcome_unknown" {
		t.Fatalf("an unknown outcome must say so: %v", err)
	}
	file := f.file()
	if file.Deposit == nil || file.Deposit.Signed == nil || !strings.HasPrefix(file.Deposit.Secret, testSecret) || !file.noNote() {
		t.Fatalf("the signed deposit and its secret must stay journaled: %+v", file.Deposit)
	}
	// While the client was down the transactions landed.
	f.funder.landOperation(file.Deposit.Signed)
	before := f.funder
	f.open() // a restarted process
	if err := f.wallet.recoverFunding(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := f.wallet.Status()
	if !status.HasNote || status.Balance != "1000000000" || status.PendingDeposit {
		t.Fatalf("recovery did not install the deposit: %+v", status)
	}
	if before.secrets != 1 || before.prepares != 1 || before.signCalls != 1 {
		t.Fatalf("recovery must not generate, prepare or sign anything new: secrets=%d prepares=%d signs=%d", before.secrets, before.prepares, before.signCalls)
	}
	if f.file().Deposit != nil || len(f.file().History) != 1 {
		t.Fatal("the journal must be cleared exactly once")
	}
}

func TestDepositRerunResumesTheSameSecretInsteadOfStartingAnother(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("timeout")}
	if _, err := f.deposit(1_000_000_000); fundingCode(err) != "deposit_outcome_unknown" {
		t.Fatal(err)
	}
	first := f.file().Deposit.Secret
	f.open()
	// The same command again (no --sol needed) resumes: the transactions are re-sent as signed.
	result, err := f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: f.payer})
	if err != nil || result.Balance != "1000000000" {
		t.Fatalf("resume: %v %+v", err, result)
	}
	if f.funder.secrets != 1 || f.funder.prepares != 1 || f.funder.signCalls != 1 {
		t.Fatalf("a resume must reuse the journaled secret and signed bytes: %+v", f.funder)
	}
	if strings.Contains(fmt.Sprint(f.file().History), first) {
		t.Fatal("secret leaked into history")
	}
	// A different amount or payer cannot hijack an unfinished deposit.
	g := newFundingFixture(t)
	g.funder.failSubmit = []error{errors.New("timeout")}
	_, _ = g.deposit(1_000_000_000)
	if _, err := g.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: g.payer, Lamports: 2_000_000_000}); fundingCode(err) != "deposit_pending" {
		t.Fatalf("different amount: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other.json")
	_ = os.WriteFile(other, []byte(config.PythSolUsdShardZeroPrice), 0600)
	if _, err := g.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: other}); fundingCode(err) != "deposit_payer_mismatch" {
		t.Fatalf("different payer: %v", err)
	}
}

func TestDepositThatExpiredBeforeLandingIsCancelledAndPreparedAgainWithTheSameSecret(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("rpc down")}
	if _, err := f.deposit(1_000_000_000); fundingCode(err) != "deposit_outcome_unknown" {
		t.Fatal(err)
	}
	stuck := f.file().Deposit
	f.funder.height = f.funder.lastValid + 10 // the blockhash is gone: it can never land
	f.funder.lastValid = f.funder.height + 150
	f.open()
	result, err := f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: f.payer})
	if err != nil || result.Balance != "1000000000" {
		t.Fatalf("resume after expiry: %v %+v", err, result)
	}
	if f.funder.secrets != 1 || f.funder.prepares != 2 {
		t.Fatalf("a fresh operation for the same secret: secrets=%d prepares=%d", f.funder.secrets, f.funder.prepares)
	}
	if len(f.funder.cancelled) != 0 {
		t.Fatalf("nothing was staged (no transaction had landed), so there is no buffer to cancel: %v", f.funder.cancelled)
	}
	note := f.funder.notes[0]
	if !note.Exists || note.Commitment != stuck.Commitment {
		t.Fatalf("the note must carry the original commitment: %+v vs %s", note, stuck.Commitment)
	}
	for id, op := range f.funder.ops {
		if op.kind == "deposit" && op.landed && id == stuck.OperationID {
			t.Fatal("the expired operation must never be sent again")
		}
	}
}

func TestDepositWhoseBufferWasStagedIsCancelledWhenItExpires(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("rpc down")}
	_, _ = f.deposit(1_000_000_000)
	stuck := f.file().Deposit
	// The first (staging) transaction landed; the executing one never will.
	f.funder.mu.Lock()
	f.funder.ops[stuck.OperationID].landed = false
	f.funder.mu.Unlock()
	f.funder.height = f.funder.lastValid + 10
	f.funder.lastValid = f.funder.height + 150
	// SignedStatus reports the first transaction as landed.
	staged := &stagedFunder{fakeFunder: f.funder, stagedID: stuck.OperationID}
	f.wallet.SetFunder(staged)
	if _, err := f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: f.payer}); err != nil {
		t.Fatal(err)
	}
	if len(f.funder.cancelled) != 1 || f.funder.cancelled[0] != stuck.OperationID {
		t.Fatalf("the staged buffer %s must be cancelled to return its rent: %v", stuck.OperationID, f.funder.cancelled)
	}
}

// stagedFunder reports the first transaction of one operation as already landed (its buffer exists).
type stagedFunder struct {
	*fakeFunder
	stagedID string
}

func (s *stagedFunder) SignedStatus(ctx context.Context, signed json.RawMessage) (SolanaSignedStatus, error) {
	status, err := s.fakeFunder.SignedStatus(ctx, signed)
	if _, id := s.fakeFunder.opOf(signed); id == s.stagedID && len(status.Transactions) > 0 {
		status.Transactions[0].Progress = "finalized"
	}
	return status, err
}

func TestDepositWhoseNoteIDIsTakenByAnotherDepositorMovesToTheNextID(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.stolenNote = true
	result, err := f.deposit(1_000_000_000)
	if err != nil || result.NoteID != 1 {
		t.Fatalf("expected note 1 after another depositor took note 0: %v %+v", err, result)
	}
	if f.funder.secrets != 1 || f.funder.prepares != 2 {
		t.Fatalf("the secret must be kept across a re-prepare: secrets=%d prepares=%d", f.funder.secrets, f.funder.prepares)
	}
	if f.funder.notes[0].Commitment != "0xsomeoneelse" || f.funder.notes[1].Commitment == "0xsomeoneelse" {
		t.Fatalf("our deposit must be note 1, the other depositor's stays note 0: %+v", f.funder.notes)
	}
}

func TestBackgroundRecoveryNeverSignsWithoutTheKeypair(t *testing.T) {
	f := newFundingFixture(t)
	// Journaled, prepared, never signed: a crash between preparing and signing.
	f.funder.failSubmit = nil
	file := f.file()
	_ = file
	if err := f.wallet.update(func(file *solanaWalletFile) {
		_, op := f.funder.newOp(&simOp{kind: "deposit", noteID: 0, commitment: "0xc01", amount: 1_000_000_000})
		noteID := uint32(0)
		file.Deposit = &pendingDeposit{Payer: testPayer, Amount: 1_000_000_000, Secret: testSecret + "1", Commitment: "0xc01", NoteID: &noteID, Operation: op, OperationID: "op01"}
	}); err != nil {
		t.Fatal(err)
	}
	err := f.wallet.recoverFunding(context.Background())
	if !errors.Is(err, errKeypairRequired) || f.funder.signCalls != 0 {
		t.Fatalf("recovery needs the keypair to sign: %v (signs=%d)", err, f.funder.signCalls)
	}
	if f.file().Deposit == nil {
		t.Fatal("the journal must survive")
	}
	// Running the command with the keypair finishes it.
	if _, err := f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: f.payer}); err != nil {
		t.Fatal(err)
	}
	if !f.wallet.Status().HasNote {
		t.Fatal("deposit did not complete")
	}
}

func TestRunSettlementRecoversAnInterruptedDepositByItself(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("killed")}
	_, _ = f.deposit(1_000_000_000)
	f.funder.landOperation(f.file().Deposit.Signed)
	f.open()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.wallet.RunSettlement(ctx, nil)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !f.wallet.Status().HasNote && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if status := f.wallet.Status(); !status.HasNote || status.PendingDeposit || status.Balance != "1000000000" {
		t.Fatalf("status after background recovery: %+v", status)
	}
}

func (f *fundingFixture) withdraw(request WithdrawRequest) (FundingResult, error) {
	if request.Destination == "" {
		request.Destination = testDestination
	}
	if request.KeypairPath == "" {
		request.KeypairPath = f.payer
	}
	return f.wallet.Withdraw(context.Background(), request)
}

func TestWithdrawAllClosesTheNoteAndPaysTheDestination(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	result, err := f.withdraw(WithdrawRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "withdrawal" || result.Lamports != 1_000_000_000 || result.Destination != testDestination || result.Signature == "" || result.Balance != "0" {
		t.Fatalf("result: %+v", result)
	}
	if f.funder.paid[testDestination] != 1_000_000_000 {
		t.Fatalf("paid out: %v", f.funder.paid)
	}
	if len(f.server.clearances) != 1 || !f.server.clearanceJournaled[0] {
		t.Fatalf("the withdrawal must be journaled (freezing the note) before clearance is requested: %v %v", f.server.clearances, f.server.clearanceJournaled)
	}
	file := f.file()
	if file.Withdrawal != nil || !file.noNote() || len(file.History) != 2 || file.History[1].Kind != "withdrawal" || file.History[1].Destination != testDestination {
		t.Fatalf("durable state: %+v", file)
	}
	if f.wallet.Status().HasNote {
		t.Fatal("a closed note must not be reported as a balance")
	}
	// The wallet can be funded again.
	if _, err := f.deposit(500_000_000); err != nil {
		t.Fatalf("deposit after a full withdrawal: %v", err)
	}
	if f.wallet.Status().Balance != "500000000" {
		t.Fatalf("status: %+v", f.wallet.Status())
	}
}

func TestWithdrawAcceptsTheExactBalanceAndRefusesAPartialAmount(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	_, err := f.withdraw(WithdrawRequest{Lamports: 400_000_000})
	if fundingCode(err) != "partial_withdrawal_unsupported" || !strings.Contains(err.Error(), "--all") {
		t.Fatalf("a partial withdrawal must be refused with the reason: %v", err)
	}
	if f.file().Withdrawal != nil || len(f.server.clearances) != 0 {
		t.Fatal("a refused withdrawal must not freeze the note or ask for clearance")
	}
	if _, err := f.withdraw(WithdrawRequest{Lamports: 1_000_000_000}); err != nil {
		t.Fatalf("the exact balance: %v", err)
	}
}

func TestWithdrawRefusesWhatItCannotDoSafely(t *testing.T) {
	f := newFundingFixture(t)
	if _, err := f.withdraw(WithdrawRequest{All: true}); fundingCode(err) != "no_note" {
		t.Fatalf("empty wallet: %v", err)
	}
	f.funded(1_000_000_000)
	if _, err := f.withdraw(WithdrawRequest{All: true, Destination: "nope"}); fundingCode(err) != "invalid_destination" {
		t.Fatalf("bad destination: %v", err)
	}
	f.chain.Balances[testPayer] = feeHeadroomLamports - 1
	if _, err := f.withdraw(WithdrawRequest{All: true}); fundingCode(err) != "insufficient_funds" {
		t.Fatalf("fee payer too poor: %v", err)
	}
	f.chain.Balances[testPayer] = 5_000_000_000
	// A tiny note is fine too: the vault also returns the note account's rent to the destination.
	g := newFundingFixture(t)
	g.funded(500_000)
	if _, err := g.withdraw(WithdrawRequest{All: true}); err != nil {
		t.Fatalf("a small note must still be withdrawable: %v", err)
	}
	if f.file().Withdrawal != nil || len(f.server.clearances) != 0 {
		t.Fatal("a refused withdrawal froze the note or asked for clearance")
	}
	// No keypair at all (and none remembered).
	h := newFundingFixture(t)
	if err := h.wallet.update(func(file *solanaWalletFile) {
		file.State = json.RawMessage(fmt.Sprintf(`{"note_id":0,"chain_id":%q,"contract_address":%q,"current_balance":1000000000}`, testChainID, testBinding))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.wallet.Withdraw(context.Background(), WithdrawRequest{All: true, Destination: testDestination}); fundingCode(err) != "keypair_required" {
		t.Fatalf("no keypair: %v", err)
	}
}

func TestWithdrawWaitsForAnOpenLeaseAndANoteWithAWithdrawalNeverLeasesAgain(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	// Move the wallet to the lease fixture's server so a lease can be opened.
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	f.server.status = func(string) (int, any) { return 200, map[string]any{"status": "active"} }
	_, err := f.withdraw(WithdrawRequest{All: true})
	if err == nil || fundingCode(err) == "" || len(f.server.clearances) != 0 {
		t.Fatalf("an open lease must block a withdrawal before any clearance: %v", err)
	}
	if f.file().Withdrawal != nil {
		t.Fatal("blocked withdrawal journaled")
	}
}

func TestWithdrawalFreezesTheNoteForLeasesUntilItCompletes(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	f.funder.failSubmit = []error{errors.New("connection reset")}
	if _, err := f.withdraw(WithdrawRequest{All: true}); fundingCode(err) != "withdrawal_outcome_unknown" {
		t.Fatalf("unknown outcome: %v", err)
	}
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); fundingCode(err) != "withdrawal_pending" {
		t.Fatalf("a frozen note must not open a lease (no double spend): %v", err)
	}
	if len(f.server.posts) != 0 {
		t.Fatal("a request reached the server for a frozen note")
	}
	if _, err := f.deposit(1_000); fundingCode(err) != "withdrawal_pending" {
		t.Fatalf("deposit during a withdrawal: %v", err)
	}
}

func TestInterruptedWithdrawalCompletesFromTheChainWithoutResending(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	f.funder.failSubmit = []error{errors.New("killed")}
	_, _ = f.withdraw(WithdrawRequest{All: true})
	pending := f.file().Withdrawal
	if pending == nil || pending.Signed == nil || pending.Clearance == nil || pending.Plan == nil {
		t.Fatalf("the clearance, proof and signed close must be journaled: %+v", pending)
	}
	f.funder.landOperation(pending.Signed) // it landed while the client was down
	submits, proofs, clearances := f.funder.submits, f.funder.proofs, len(f.server.clearances)
	f.open()
	if err := f.wallet.recoverFunding(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.funder.submits != submits || f.funder.proofs != proofs || len(f.server.clearances) != clearances {
		t.Fatal("recovery re-sent, re-proved or re-requested clearance although the chain showed the close")
	}
	if f.wallet.Status().HasNote || f.wallet.Status().PendingWithdrawal || f.funder.paid[testDestination] != 1_000_000_000 {
		t.Fatalf("status %+v paid %v", f.wallet.Status(), f.funder.paid)
	}
}

func TestWithdrawalReprovesAStaleRootAndResumesFromTheClearance(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	f.funder.staleRoots = 2
	if _, err := f.withdraw(WithdrawRequest{All: true}); err != nil {
		t.Fatal(err)
	}
	if f.funder.proofs != 3 || len(f.server.clearances) != 1 {
		t.Fatalf("two stale roots mean three proofs from one clearance: proofs=%d clearances=%d", f.funder.proofs, len(f.server.clearances))
	}
}

func TestWithdrawalThatExpiredIsResignedWithoutAskingForClearanceAgain(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	f.funder.failSubmit = []error{errors.New("rpc down")}
	_, _ = f.withdraw(WithdrawRequest{All: true})
	stuck := f.file().Withdrawal
	f.funder.height = f.funder.lastValid + 10
	f.funder.lastValid = f.funder.height + 150
	f.open()
	if _, err := f.wallet.Withdraw(context.Background(), WithdrawRequest{Destination: testDestination, KeypairPath: f.payer, All: true}); err != nil {
		t.Fatal(err)
	}
	if len(f.server.clearances) != 1 || f.funder.proofs != 2 {
		t.Fatalf("the clearance is reused, the proof redone: clearances=%d proofs=%d", len(f.server.clearances), f.funder.proofs)
	}
	if f.funder.ops[stuck.OperationID].landed {
		t.Fatal("the expired close must never land")
	}
	if f.funder.paid[testDestination] != 1_000_000_000 {
		t.Fatalf("paid %v", f.funder.paid)
	}
}

func TestResumedWithdrawalCannotBeRedirected(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	f.funder.failSubmit = []error{errors.New("rpc down")}
	_, _ = f.withdraw(WithdrawRequest{All: true})
	if _, err := f.withdraw(WithdrawRequest{All: true, Destination: config.PythReceiverProgram}); fundingCode(err) != "withdrawal_pending" {
		t.Fatalf("a different destination: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other.json")
	_ = os.WriteFile(other, []byte(config.PythSolUsdShardZeroPrice), 0600)
	if _, err := f.withdraw(WithdrawRequest{All: true, KeypairPath: other}); fundingCode(err) != "withdrawal_payer_mismatch" {
		t.Fatalf("a different fee payer: %v", err)
	}
	if _, err := f.withdraw(WithdrawRequest{All: true}); err != nil {
		t.Fatalf("the same command finishes it: %v", err)
	}
}

func TestWithdrawalRefusedClearanceLeavesTheNoteFrozenAndResumable(t *testing.T) {
	f := newFundingFixture(t)
	f.funded(1_000_000_000)
	f.server.clearance = func(string) (int, any) { return 500, map[string]any{"error_code": "internal"} }
	if _, err := f.withdraw(WithdrawRequest{All: true}); fundingCode(err) != "clearance_refused" {
		t.Fatal(err)
	}
	if f.file().Withdrawal == nil {
		t.Fatal("once clearance may have been issued the note stays frozen")
	}
	f.server.clearance = nil
	if _, err := f.withdraw(WithdrawRequest{All: true}); err != nil {
		t.Fatalf("resume: %v", err)
	}
}

func TestFundingFailsWithoutAHelper(t *testing.T) {
	f := newFundingFixture(t)
	f.wallet.SetFunder(nil)
	if _, err := f.deposit(1); fundingCode(err) != "funding_not_configured" {
		t.Fatal(err)
	}
	if _, err := f.withdraw(WithdrawRequest{All: true}); fundingCode(err) != "funding_not_configured" {
		t.Fatal(err)
	}
}

func TestAdminAPIFundsWithdrawsAndRefusesUnconfirmedRequests(t *testing.T) {
	f := newFundingFixture(t)
	call := func(method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest(method, path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.wallet.ServeAdminHTTP(recorder, request)
		var reply map[string]any
		_ = json.Unmarshal(recorder.Body.Bytes(), &reply)
		return recorder.Code, reply
	}
	if status, _ := call(http.MethodPost, "/admin/solana/deposit", map[string]any{"keypair": f.payer, "lamports": 1_000_000_000}); status == http.StatusOK || f.funder.secrets != 0 {
		t.Fatalf("an unconfirmed deposit ran (status %d)", status)
	}
	status, reply := call(http.MethodPost, "/admin/solana/deposit", map[string]any{"keypair": f.payer, "lamports": 1_000_000_000, "confirm": true})
	if status != http.StatusOK || reply["kind"] != "deposit" || reply["private_balance_lamports"] != "1000000000" {
		t.Fatalf("deposit: %d %v", status, reply)
	}
	if status, reply := call(http.MethodPost, "/admin/solana/deposit", map[string]any{"keypair": f.payer, "lamports": 1, "confirm": true}); status != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(reply["error"]), "already holds a funded note") {
		t.Fatalf("a refusal is a 422 with its reason: %d %v", status, reply)
	}
	if status, reply := call(http.MethodGet, "/admin/solana/status", nil); status != http.StatusOK || reply["has_note"] != true {
		t.Fatalf("status: %d %v", status, reply)
	}
	if status, _ := call(http.MethodPost, "/admin/solana/withdraw", map[string]any{"to": testDestination, "all": true}); status == http.StatusOK || len(f.server.clearances) != 0 {
		t.Fatalf("an unconfirmed withdrawal ran (status %d)", status)
	}
	status, reply = call(http.MethodPost, "/admin/solana/withdraw", map[string]any{"to": testDestination, "all": true, "confirm": true})
	if status != http.StatusOK || reply["kind"] != "withdrawal" || reply["destination"] != testDestination || f.funder.paid[testDestination] != 1_000_000_000 {
		t.Fatalf("withdrawal: %d %v", status, reply)
	}
	if status, _ := call(http.MethodPost, "/admin/solana/unknown", map[string]any{}); status != http.StatusNotFound {
		t.Fatalf("unknown endpoint: %d", status)
	}
	if status, _ := call(http.MethodPost, "/admin/solana/withdraw", map[string]any{"to": testDestination, "surprise": 1, "confirm": true}); status == http.StatusOK {
		t.Fatal("an unknown field was accepted")
	}
}

func TestBufferCancellationSurvivesRPCFailureAndRestart(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("rpc down")}
	_, _ = f.deposit(1_000_000_000)
	stuck := f.file().Deposit
	f.funder.height = f.funder.lastValid + 10
	f.funder.lastValid = f.funder.height + 150
	f.wallet.SetFunder(&stagedFunder{fakeFunder: f.funder, stagedID: stuck.OperationID})
	f.funder.failSubmit = []error{errors.New("cancellation rpc down")}
	if _, err := f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: f.payer}); err == nil {
		t.Fatal("expected cancellation failure")
	}
	file := f.file()
	if file.Cleanup == nil || file.Cleanup.Signed == nil || file.Deposit.OperationID != stuck.OperationID {
		t.Fatal("cancellation failure lost the signed bytes or original buffer")
	}
	signs := f.funder.signCalls
	f.open()
	f.wallet.SetFunder(&stagedFunder{fakeFunder: f.funder, stagedID: stuck.OperationID})
	if err := f.wallet.cancelOperation(context.Background(), "", stuck.Payer, stuck.OperationID); err != nil {
		t.Fatal(err)
	}
	if f.file().Cleanup != nil || f.funder.signCalls != signs {
		t.Fatal("restart must recover exact signed cancellation without keypair")
	}
}

func TestBackgroundBufferResetRetainsIdentityUntilKeypairIsProvided(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("rpc down")}
	_, _ = f.deposit(1_000_000_000)
	stuck := *f.file().Deposit
	if err := f.wallet.resetDepositOperation(context.Background(), "", stuck, true); !errors.Is(err, errKeypairRequired) {
		t.Fatal(err)
	}
	if file := f.file(); file.Cleanup == nil || file.Deposit.OperationID != stuck.OperationID {
		t.Fatal("background reset forgot the staged buffer")
	}
}

func TestFailedCleanupSaveCannotPublishUnsavedSignedBytes(t *testing.T) {
	f := newFundingFixture(t)
	if err := f.wallet.update(func(file *solanaWalletFile) {
		file.Cleanup = &pendingCancellation{Payer: testPayer, OperationID: "old"}
	}); err != nil {
		t.Fatal(err)
	}
	before := f.wallet.snapshot()
	realPath := f.wallet.path
	f.wallet.path = filepath.Join(f.payer, "wallet.json") // parent is a regular file: saving must fail
	if err := f.wallet.update(func(file *solanaWalletFile) { file.Cleanup.Signed = json.RawMessage(`{"signed":true}`) }); errorCode(err) != "wallet_storage_failed" {
		t.Fatal(err)
	}
	f.wallet.path = realPath
	if before.Cleanup.Signed != nil || f.wallet.snapshot().Cleanup.Signed != nil || f.file().Cleanup.Signed != nil {
		t.Fatal("failed save changed a snapshot or published undurable cancellation bytes")
	}
}

func TestProvisionalFailuresCannotAuthorizeReset(t *testing.T) {
	for _, progress := range []string{"unknown", "processed", "confirmed"} {
		if (SolanaSignedStatus{Transactions: []SolanaTxState{{Progress: progress, Failed: true}}}).anyFailed() {
			t.Fatalf("%s failure authorized reset", progress)
		}
	}
	if !(SolanaSignedStatus{Transactions: []SolanaTxState{{Progress: "finalized", Failed: true}}}).anyFailed() {
		t.Fatal("finalized failure must authorize recovery")
	}
}

func TestResetRetainsOriginalDepositThatFinalizedDuringCancellation(t *testing.T) {
	f := newFundingFixture(t)
	f.funder.failSubmit = []error{errors.New("rpc down")}
	_, _ = f.deposit(1_000_000_000)
	stuck := *f.file().Deposit
	f.funder.landOperation(stuck.Signed)
	if err := f.wallet.resetDepositOperation(context.Background(), f.payer, stuck, false); err != nil {
		t.Fatal(err)
	}
	if f.file().Deposit.NoteID == nil || *f.file().Deposit.NoteID != *stuck.NoteID {
		t.Fatal("reset erased the funded note identity")
	}
	if result, err := f.wallet.Deposit(context.Background(), DepositRequest{KeypairPath: f.payer}); err != nil || result.NoteID != *stuck.NoteID {
		t.Fatalf("failed to recover original deposit: %+v %v", result, err)
	}
	if f.funder.prepares != 1 {
		t.Fatal("recovery prepared a duplicate deposit")
	}
}
