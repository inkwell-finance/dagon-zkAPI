package zkapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// FundingError is a funding refusal with a stable code. Its message is meant for
// the person at the terminal and never contains wallet secrets.
type FundingError struct {
	Code    string
	Message string
}

func (e *FundingError) Error() string { return e.Message }

func fundingErr(code, format string, args ...any) error {
	return &FundingError{Code: code, Message: fmt.Sprintf(format, args...)}
}

const (
	// feeHeadroomLamports is what the funding keypair must hold beyond the amount it deposits: transaction fees and
	// the rent of the staged operation buffer and the note account (the buffer's rent is returned by the vault).
	feeHeadroomLamports = 50_000_000
	// maxFundingSteps bounds the state machine's iterations in one command; maxFundingResets bounds how often it
	// abandons an operation whose transactions can no longer land (or whose proof went stale) and starts that step over.
	maxFundingSteps  = 60
	maxFundingResets = 6
	staleRootPause   = 5 * time.Second
)

// errKeypairRequired is returned when background recovery reaches a step that
// needs the funding keypair. The wallet stays journaled; the user finishes it
// by running the command again with --keypair.
var errKeypairRequired = fundingErr("keypair_required", "this funding operation needs the funding keypair to continue: run the same zkapi-clientd solana command again with --keypair")

// pendingDeposit is the durable record of a deposit from before its first chain
// interaction until the note is installed. It holds the note secret: it is
// written (fsync + rename) BEFORE anything touches the chain, so a crash can
// never leave a deposit whose secret was lost.
type pendingDeposit struct {
	Payer       string          `json:"payer"`
	Amount      uint64          `json:"amount"`
	Secret      string          `json:"secret"`
	Commitment  string          `json:"commitment"`
	NoteID      *uint32         `json:"note_id,omitempty"`
	Operation   json.RawMessage `json:"operation,omitempty"` // unsigned staged transactions
	OperationID string          `json:"operation_id,omitempty"`
	Signed      json.RawMessage `json:"signed,omitempty"` // the exact signed bytes; re-sendable, never re-signed
	CreatedAt   uint64          `json:"created_at"`
}

// pendingWithdrawal is the durable record of a mutual close. Its existence
// freezes the note: no lease is opened against it any more.
type pendingWithdrawal struct {
	Destination string          `json:"destination"`
	NoteID      uint32          `json:"note_id"`
	Nullifier   string          `json:"nullifier"`
	Lamports    uint64          `json:"lamports"`
	Payer       string          `json:"payer"`
	Clearance   json.RawMessage `json:"clearance,omitempty"`
	Plan        json.RawMessage `json:"plan,omitempty"` // proof of the close
	Operation   json.RawMessage `json:"operation,omitempty"`
	OperationID string          `json:"operation_id,omitempty"`
	Signed      json.RawMessage `json:"signed,omitempty"`
	CreatedAt   uint64          `json:"created_at"`
}

// pendingCancellation keeps the abandoned buffer identity and exact signed
// cancellation durable until finalized or confirmed absent on the chain.
type pendingCancellation struct {
	Payer       string          `json:"payer"`
	OperationID string          `json:"operation_id"`
	Signed      json.RawMessage `json:"signed,omitempty"`
}

// fundingRecord is the non-secret history of completed funding operations.
type fundingRecord struct {
	Kind        string `json:"kind"` // deposit or withdrawal
	At          uint64 `json:"at"`
	Lamports    uint64 `json:"lamports"`
	NoteID      uint32 `json:"note_id"`
	Destination string `json:"destination,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

// FundingResult reports a completed deposit or withdrawal.
type FundingResult struct {
	Kind        string `json:"kind"`
	Lamports    uint64 `json:"lamports"`
	NoteID      uint32 `json:"note_id"`
	Signature   string `json:"signature,omitempty"`
	Destination string `json:"destination,omitempty"`
	Balance     string `json:"private_balance_lamports"`
}

// DepositRequest funds the wallet from a local keypair file.
type DepositRequest struct {
	KeypairPath string
	Lamports    uint64
}

// WithdrawRequest pays the wallet's whole note out to a Solana address. The
// vault closes a note as a whole, so there are no partial withdrawals: All must
// be set, or Lamports must equal the note's balance exactly.
type WithdrawRequest struct {
	Destination string
	KeypairPath string // fee payer; defaults to the keypair of the last deposit
	All         bool
	Lamports    uint64
}

// SetFunder installs the funding helper. OpenSolanaWallet does it automatically
// for a prover that also implements SolanaFunder.
func (w *SolanaWallet) SetFunder(funder SolanaFunder) { w.funder = funder }

func (w *SolanaWallet) requireFunder() error {
	if w.funder == nil {
		return fundingErr("funding_not_configured", "funding needs the Solana wallet helper: set prover_binary, prover_sha256 and proof_setup_dir in the profile")
	}
	return nil
}

func (w *SolanaWallet) rpc() *solanaRPC { return &solanaRPC{http: w.http, url: w.pin.RPCURL} }

// VerifyChain checks the pinned deployment against the chain (see VerifySolanaChain).
func (w *SolanaWallet) VerifyChain(ctx context.Context) (SolanaVault, error) {
	return VerifySolanaChain(ctx, w.http, w.pin)
}

// InitSolanaWallet creates an empty wallet (configuration only, no note) for the
// pinned deployment, so a first deposit has somewhere durable to journal. The
// configuration is derived by the helper exactly as the vault derives its identity.
func InitSolanaWallet(ctx context.Context, dir string, pin config.Solana, funder SolanaFunder) error {
	if err := pin.Validate(); err != nil {
		return err
	}
	path := solanaWalletPath(dir, pin)
	if _, err := os.Lstat(path); err == nil {
		return errors.New("a wallet already exists for this deployment")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cfg, err := funder.WalletConfig(ctx, pin)
	if err != nil {
		return err
	}
	file := solanaWalletFile{Version: solanaWalletVersion, Deployment: identityOf(pin), Config: cfg}
	if err := file.check(pin); err != nil {
		return err
	}
	return file.save(path)
}

// Deposit moves native SOL from the keypair into the vault and installs the new
// note. It resumes an unfinished deposit instead of starting a second one.
func (w *SolanaWallet) Deposit(ctx context.Context, req DepositRequest) (FundingResult, error) {
	if err := w.requireFunder(); err != nil {
		return FundingResult{}, err
	}
	release, err := w.acquire(ctx)
	if err != nil {
		return FundingResult{}, err
	}
	defer release()
	file := w.snapshot()
	if file.Withdrawal != nil {
		return FundingResult{}, fundingErr("withdrawal_pending", "a withdrawal is unfinished; finish it with zkapi-clientd solana withdraw first")
	}
	if _, err := w.VerifyChain(ctx); err != nil {
		return FundingResult{}, err
	}
	if file.Deposit == nil {
		if note, err := file.note(); err == nil {
			return FundingResult{}, fundingErr("note_exists", "this wallet already holds a funded note (%s lamports); withdraw it before depositing again", note.CurrentBalance)
		}
		if file.hasJournal() {
			return FundingResult{}, &Error{http.StatusConflict, "lease_pending"}
		}
		if req.Lamports == 0 || req.Lamports > maxSafeInteger {
			return FundingResult{}, fundingErr("invalid_amount", "the deposit amount must be positive")
		}
		if req.KeypairPath == "" {
			return FundingResult{}, fundingErr("keypair_required", "a deposit needs --keypair FILE")
		}
		payer, err := w.funder.KeypairPubkey(ctx, req.KeypairPath)
		if err != nil {
			return FundingResult{}, err
		}
		have, err := w.rpc().balance(ctx, payer)
		if err != nil {
			return FundingResult{}, err
		}
		if have < req.Lamports+feeHeadroomLamports {
			return FundingResult{}, fundingErr("insufficient_funds", "the funding keypair %s holds %s lamports; a deposit of %s needs %s more for fees and refundable rent",
				short(payer), commas(have), commas(req.Lamports), commas(feeHeadroomLamports))
		}
		params, err := w.funder.DepositParams(ctx)
		if err != nil {
			return FundingResult{}, err
		}
		// The secret is durable before the chain is touched.
		deposit := &pendingDeposit{Payer: payer, Amount: req.Lamports, Secret: params.Secret, Commitment: params.Commitment, CreatedAt: w.unix()}
		if err := w.update(func(f *solanaWalletFile) { f.Deposit, f.Keypair = deposit, req.KeypairPath }); err != nil {
			return FundingResult{}, err
		}
	} else {
		if req.Lamports != 0 && req.Lamports != file.Deposit.Amount {
			return FundingResult{}, fundingErr("deposit_pending", "an unfinished deposit of %s lamports exists; finish it before starting another", commas(file.Deposit.Amount))
		}
		if req.KeypairPath != "" {
			payer, err := w.funder.KeypairPubkey(ctx, req.KeypairPath)
			if err != nil {
				return FundingResult{}, err
			}
			if payer != file.Deposit.Payer {
				return FundingResult{}, fundingErr("deposit_payer_mismatch", "the unfinished deposit was funded by %s; use that keypair to finish it", short(file.Deposit.Payer))
			}
		}
	}
	return w.driveDeposit(ctx, req.KeypairPath)
}

// driveDeposit advances the journaled deposit as far as the chain allows. Every
// decision is made from the chain's state, so it is safe after any crash.
func (w *SolanaWallet) driveDeposit(ctx context.Context, keypair string) (FundingResult, error) {
	if cleanup := w.snapshot().Cleanup; cleanup != nil {
		if err := w.cancelOperation(ctx, keypair, cleanup.Payer, cleanup.OperationID); err != nil {
			return FundingResult{}, err
		}
	}
	resets := 0
	for step := 0; step < maxFundingSteps && resets <= maxFundingResets; step++ {
		d := *w.snapshot().Deposit
		if d.NoteID != nil {
			note, err := w.funder.NoteStatus(ctx, *d.NoteID)
			if err != nil {
				return FundingResult{}, err
			}
			if note.Exists {
				if config.SameFelt(note.Commitment, d.Commitment) && note.Amount == d.Amount {
					return w.finishDeposit(ctx, d, note)
				}
				// Another depositor took this note ID: this operation can never land.
				resets++
				if err := w.resetDepositOperation(ctx, keypair, d, true); err != nil {
					return FundingResult{}, err
				}
				continue
			}
		}
		switch {
		case d.Signed != nil:
			status, err := w.funder.SignedStatus(ctx, d.Signed)
			if err != nil {
				return FundingResult{}, err
			}
			switch {
			case status.allFinalized():
				continue // the note account is read at the top of the next round
			case status.anyFailed() || status.Expired:
				resets++
				if err := w.resetDepositOperation(ctx, keypair, d, len(status.Transactions) > 0 && status.Transactions[0].Progress != "unknown"); err != nil {
					return FundingResult{}, err
				}
				continue
			}
			if _, err := w.funder.SubmitSigned(ctx, d.Signed, true); err != nil {
				switch helperCode(err) {
				case helperBlockhash, helperTransactionBad:
					resets++
					if err := w.resetDepositOperation(ctx, keypair, d, true); err != nil {
						return FundingResult{}, err
					}
					continue
				}
				return FundingResult{}, fundingErr("deposit_outcome_unknown", "the deposit's transactions may still land; run the command again, or restart zkapi-clientd serve, to recover from the chain")
			}
		case d.Operation != nil:
			if keypair == "" {
				return FundingResult{}, errKeypairRequired
			}
			signed, err := w.funder.SignOperation(ctx, keypair, d.Operation)
			if err != nil {
				return FundingResult{}, err
			}
			if err := w.update(func(f *solanaWalletFile) { f.Deposit.Signed = signed }); err != nil {
				return FundingResult{}, err
			}
		default:
			noteID, operation, err := w.funder.PrepareDeposit(ctx, d.Payer, d.Commitment, d.Amount)
			if err != nil {
				switch helperCode(err) {
				case helperStaleRoot, helperStaleNote:
					// The finalized indexer trails the chain; look again shortly.
					resets++
					if err := w.sleep(ctx, staleRootPause); err != nil {
						return FundingResult{}, err
					}
					continue
				}
				return FundingResult{}, err
			}
			id := operationID(operation)
			if err := w.update(func(f *solanaWalletFile) {
				f.Deposit.NoteID, f.Deposit.Operation, f.Deposit.OperationID = &noteID, operation, id
			}); err != nil {
				return FundingResult{}, err
			}
		}
	}
	return FundingResult{}, fundingErr("deposit_pending", "the deposit is not final yet; run zkapi-clientd solana deposit again (or let zkapi-clientd serve recover it) to continue from the chain")
}

// resetDepositOperation abandons an operation whose transactions can no longer
// land, closing its staged buffer to return the rent. The note secret and
// commitment are kept: the next round prepares a fresh operation for them.
func (w *SolanaWallet) resetDepositOperation(ctx context.Context, keypair string, d pendingDeposit, buffered bool) error {
	if buffered && d.OperationID != "" {
		if err := w.cancelOperation(ctx, keypair, d.Payer, d.OperationID); err != nil {
			return err
		}
	}
	// Cancellation can race completion. Keep the original note identity when its
	// deposit finalized, so the next drive iteration installs it instead of funding twice.
	if d.NoteID != nil {
		note, err := w.funder.NoteStatus(ctx, *d.NoteID)
		if err != nil {
			return err
		}
		if note.Exists && config.SameFelt(note.Commitment, d.Commitment) && note.Amount == d.Amount {
			return nil
		}
	}
	return w.update(func(f *solanaWalletFile) {
		f.Deposit.NoteID, f.Deposit.Operation, f.Deposit.OperationID, f.Deposit.Signed = nil, nil, "", nil
	})
}

// cancelOperation blocks resetting the original operation until cleanup is durable
// and finalized. Unknown outcomes keep the exact signed bytes for restart recovery.
func (w *SolanaWallet) cancelOperation(ctx context.Context, keypair, payer, id string) error {
	cleanup := w.snapshot().Cleanup
	if cleanup == nil {
		if err := w.update(func(f *solanaWalletFile) { f.Cleanup = &pendingCancellation{Payer: payer, OperationID: id} }); err != nil {
			return err
		}
		cleanup = w.snapshot().Cleanup
	}
	if cleanup.Payer != payer || cleanup.OperationID != id {
		return fundingErr("cleanup_pending", "another staged buffer must be recovered first")
	}
	clear := func() error { return w.update(func(f *solanaWalletFile) { f.Cleanup = nil }) }
	if cleanup.Signed != nil {
		status, err := w.funder.SignedStatus(ctx, cleanup.Signed)
		if err != nil {
			return err
		}
		if status.allFinalized() {
			return clear()
		}
		if status.Expired || status.anyFailed() {
			if err := w.update(func(f *solanaWalletFile) { f.Cleanup.Signed = nil }); err != nil {
				return err
			}
			cleanup = w.snapshot().Cleanup
		}
	}
	if cleanup.Signed == nil {
		operation, err := w.funder.PrepareCancel(ctx, payer, id)
		if helperCode(err) == "buffer_absent" {
			return clear()
		}
		if err != nil {
			return err
		}
		if keypair == "" {
			return errKeypairRequired
		}
		signed, err := w.funder.SignOperation(ctx, keypair, operation)
		if err != nil {
			return err
		}
		if err := w.update(func(f *solanaWalletFile) { f.Cleanup.Signed = signed }); err != nil {
			return err
		}
		cleanup = w.snapshot().Cleanup
	}
	if _, err := w.funder.SubmitSigned(ctx, cleanup.Signed, true); err != nil {
		return err
	}
	status, err := w.funder.SignedStatus(ctx, cleanup.Signed)
	if err != nil {
		return err
	}
	if !status.allFinalized() {
		return fundingErr("cleanup_pending", "staged buffer cancellation is not final; retry to resume it")
	}
	return clear()
}

func (w *SolanaWallet) finishDeposit(ctx context.Context, d pendingDeposit, note SolanaNoteInfo) (FundingResult, error) {
	file := w.snapshot()
	state, err := w.funder.ConfirmDeposit(ctx, file.Config, d.Secret, *d.NoteID, d.Amount, note.Expiry)
	if err != nil {
		return FundingResult{}, err
	}
	signature := lastSignature(d.Signed)
	record := fundingRecord{Kind: "deposit", At: w.unix(), Lamports: d.Amount, NoteID: *d.NoteID, Signature: signature}
	if err := w.update(func(f *solanaWalletFile) {
		f.State, f.Deposit = state, nil
		f.History = append(f.History, record)
	}); err != nil {
		return FundingResult{}, err
	}
	return FundingResult{Kind: "deposit", Lamports: d.Amount, NoteID: *d.NoteID, Signature: signature, Balance: w.Status().Balance}, nil
}

// Withdraw closes the wallet's note and pays its whole balance to a Solana
// address. It follows the browser SDK's mutual close: the server's clearance
// (which freezes the note against further requests), a withdrawal proof, then the
// vault's staged close, paid for by the funding keypair.
func (w *SolanaWallet) Withdraw(ctx context.Context, req WithdrawRequest) (FundingResult, error) {
	if err := w.requireFunder(); err != nil {
		return FundingResult{}, err
	}
	release, err := w.acquire(ctx)
	if err != nil {
		return FundingResult{}, err
	}
	defer release()
	file := w.snapshot()
	if file.Deposit != nil {
		return FundingResult{}, fundingErr("deposit_pending", "a deposit is unfinished; finish it with zkapi-clientd solana deposit first")
	}
	if _, err := w.VerifyChain(ctx); err != nil {
		return FundingResult{}, err
	}
	if file.Withdrawal == nil {
		if err := w.recoverLocked(ctx); err != nil {
			return FundingResult{}, err
		}
		file = w.snapshot()
		if file.hasJournal() {
			return FundingResult{}, fundingErr("lease_pending", "a lease is still open; close it first with zkapi-clientd lease settle --confirm")
		}
		note, err := file.note()
		if err != nil {
			return FundingResult{}, fundingErr("no_note", "this wallet holds no funded note")
		}
		balance, _ := new(big.Int).SetString(note.CurrentBalance.String(), 10)
		if !balance.IsUint64() || balance.Sign() <= 0 {
			return FundingResult{}, fundingErr("no_balance", "this wallet's note has no balance left to withdraw")
		}
		lamports := balance.Uint64()
		if !req.All && req.Lamports != lamports {
			return FundingResult{}, fundingErr("partial_withdrawal_unsupported",
				"the vault closes a note as a whole: the whole private balance is %s lamports. Use --all (or --sol %s); to keep some funds private, withdraw all and deposit the remainder again", commas(lamports), solText(lamports))
		}
		if !config.Base58Account(req.Destination) {
			return FundingResult{}, fundingErr("invalid_destination", "the destination must be a base58 Solana address")
		}
		if req.KeypairPath == "" {
			req.KeypairPath = file.Keypair
		}
		if req.KeypairPath == "" {
			return FundingResult{}, fundingErr("keypair_required", "a withdrawal needs --keypair FILE: it pays the transaction fees")
		}
		payer, err := w.funder.KeypairPubkey(ctx, req.KeypairPath)
		if err != nil {
			return FundingResult{}, err
		}
		have, err := w.rpc().balance(ctx, payer)
		if err != nil {
			return FundingResult{}, err
		}
		if have < feeHeadroomLamports {
			return FundingResult{}, fundingErr("insufficient_funds", "the fee payer %s holds %s lamports; closing a note needs about %s for fees and refundable rent", short(payer), commas(have), commas(feeHeadroomLamports))
		}
		nullifier, err := w.funder.WithdrawalNullifier(ctx, file.Config, file.State)
		if err != nil {
			return FundingResult{}, err
		}
		withdrawal := &pendingWithdrawal{Destination: req.Destination, NoteID: note.NoteID, Nullifier: nullifier, Lamports: lamports, Payer: payer, CreatedAt: w.unix()}
		// From here on the note is frozen: leases refuse it until the close completes.
		if err := w.update(func(f *solanaWalletFile) { f.Withdrawal, f.Keypair = withdrawal, req.KeypairPath }); err != nil {
			return FundingResult{}, err
		}
	} else {
		pending := file.Withdrawal
		if req.Destination != "" && req.Destination != pending.Destination {
			return FundingResult{}, fundingErr("withdrawal_pending", "an unfinished withdrawal to %s exists; finish it (same --to) before starting another", pending.Destination)
		}
		if req.KeypairPath != "" {
			payer, err := w.funder.KeypairPubkey(ctx, req.KeypairPath)
			if err != nil {
				return FundingResult{}, err
			}
			if payer != pending.Payer {
				return FundingResult{}, fundingErr("withdrawal_payer_mismatch", "the unfinished withdrawal is paid by %s; use that keypair to finish it", short(pending.Payer))
			}
		}
	}
	if req.KeypairPath == "" {
		req.KeypairPath = w.snapshot().Keypair
	}
	return w.driveWithdrawal(ctx, req.KeypairPath)
}

func (w *SolanaWallet) driveWithdrawal(ctx context.Context, keypair string) (FundingResult, error) {
	if cleanup := w.snapshot().Cleanup; cleanup != nil {
		if err := w.cancelOperation(ctx, keypair, cleanup.Payer, cleanup.OperationID); err != nil {
			return FundingResult{}, err
		}
	}
	resets := 0
	for step := 0; step < maxFundingSteps && resets <= maxFundingResets; step++ {
		d := *w.snapshot().Withdrawal
		used, err := w.funder.NullifierUsed(ctx, d.Nullifier)
		if err != nil {
			return FundingResult{}, err
		}
		if used {
			return w.finishWithdrawal(ctx, d)
		}
		switch {
		case d.Signed != nil:
			status, err := w.funder.SignedStatus(ctx, d.Signed)
			if err != nil {
				return FundingResult{}, err
			}
			switch {
			case status.allFinalized():
				continue
			case status.anyFailed() || status.Expired:
				resets++
				if err := w.resetWithdrawalOperation(ctx, keypair, d, len(status.Transactions) > 0 && status.Transactions[0].Progress != "unknown"); err != nil {
					return FundingResult{}, err
				}
				continue
			}
			if _, err := w.funder.SubmitSigned(ctx, d.Signed, true); err != nil {
				switch helperCode(err) {
				case helperBlockhash, helperTransactionBad:
					resets++
					if err := w.resetWithdrawalOperation(ctx, keypair, d, true); err != nil {
						return FundingResult{}, err
					}
					continue
				}
				return FundingResult{}, fundingErr("withdrawal_outcome_unknown", "the withdrawal's transactions may still land; run the command again, or restart zkapi-clientd serve, to recover from the chain")
			}
		case d.Operation != nil:
			if keypair == "" {
				return FundingResult{}, errKeypairRequired
			}
			signed, err := w.funder.SignOperation(ctx, keypair, d.Operation)
			if err != nil {
				return FundingResult{}, err
			}
			if err := w.update(func(f *solanaWalletFile) { f.Withdrawal.Signed = signed }); err != nil {
				return FundingResult{}, err
			}
		case d.Plan != nil:
			operation, err := w.funder.PrepareWithdrawal(ctx, d.Payer, d.Destination, d.Plan)
			if err != nil {
				if helperCode(err) == helperStaleRoot {
					// The tree moved under the proof: prove again from a fresh snapshot.
					resets++
					if err := w.update(func(f *solanaWalletFile) { f.Withdrawal.Plan = nil }); err != nil {
						return FundingResult{}, err
					}
					if err := w.sleep(ctx, staleRootPause); err != nil {
						return FundingResult{}, err
					}
					continue
				}
				return FundingResult{}, err
			}
			id := operationID(operation)
			if err := w.update(func(f *solanaWalletFile) { f.Withdrawal.Operation, f.Withdrawal.OperationID = operation, id }); err != nil {
				return FundingResult{}, err
			}
		case d.Clearance != nil:
			file := w.snapshot()
			snapshot, err := w.remote(ctx, http.MethodGet, w.pin.IndexerURL, "/v1/tree/snapshot", nil)
			if err != nil {
				return FundingResult{}, err
			}
			plan, err := w.funder.ProveWithdrawal(ctx, file.Config, file.State, SolanaWithdrawInput{Destination: d.Destination, Snapshot: snapshot, NoteID: d.NoteID, Clearance: d.Clearance})
			if err != nil {
				return FundingResult{}, err
			}
			if err := w.update(func(f *solanaWalletFile) { f.Withdrawal.Plan = plan }); err != nil {
				return FundingResult{}, err
			}
		default:
			if err := w.checkAttestation(ctx); err != nil {
				return FundingResult{}, err
			}
			body, _ := json.Marshal(map[string]string{"withdrawal_nullifier": d.Nullifier})
			raw, err := w.server(ctx, http.MethodPost, "/v2/withdraw/clearance", body)
			if err != nil {
				return FundingResult{}, fundingErr("clearance_refused", "the server did not clear the withdrawal: %v", err)
			}
			var answer struct {
				Status    string `json:"status"`
				Nullifier string `json:"withdrawal_nullifier"`
			}
			if json.Unmarshal(raw, &answer) != nil || answer.Status != "ok" || !config.SameFelt(answer.Nullifier, d.Nullifier) {
				return FundingResult{}, &Error{http.StatusBadGateway, "invalid_solana_clearance"}
			}
			if err := w.update(func(f *solanaWalletFile) { f.Withdrawal.Clearance = raw }); err != nil {
				return FundingResult{}, err
			}
		}
	}
	return FundingResult{}, fundingErr("withdrawal_pending", "the withdrawal is not final yet; run zkapi-clientd solana withdraw again (or let zkapi-clientd serve recover it) to continue from the chain")
}

func (w *SolanaWallet) resetWithdrawalOperation(ctx context.Context, keypair string, d pendingWithdrawal, buffered bool) error {
	if buffered && d.OperationID != "" {
		if err := w.cancelOperation(ctx, keypair, d.Payer, d.OperationID); err != nil {
			return err
		}
	}
	used, err := w.funder.NullifierUsed(ctx, d.Nullifier)
	if err != nil {
		return err
	}
	if used {
		return nil
	} // preserve the close identity; next iteration finishes its finalized result
	// The clearance stays valid (a signature over the nullifier); the proof is bound to a tree root, so redo it.
	return w.update(func(f *solanaWalletFile) {
		f.Withdrawal.Plan, f.Withdrawal.Operation, f.Withdrawal.OperationID, f.Withdrawal.Signed = nil, nil, "", nil
	})
}

func (w *SolanaWallet) finishWithdrawal(ctx context.Context, d pendingWithdrawal) (FundingResult, error) {
	note, err := w.funder.NoteStatus(ctx, d.NoteID)
	if err != nil {
		return FundingResult{}, err
	}
	if note.Exists {
		return FundingResult{}, fundingErr("withdrawal_inconsistent", "the withdrawal's nullifier is used on chain but the note account still exists; do not retry, investigate")
	}
	signature := lastSignature(d.Signed)
	record := fundingRecord{Kind: "withdrawal", At: w.unix(), Lamports: d.Lamports, NoteID: d.NoteID, Destination: d.Destination, Signature: signature}
	if err := w.update(func(f *solanaWalletFile) {
		f.State, f.Withdrawal, f.Lease, f.Journal = nil, nil, nil, nil
		f.History = append(f.History, record)
	}); err != nil {
		return FundingResult{}, err
	}
	return FundingResult{Kind: "withdrawal", Lamports: d.Lamports, NoteID: d.NoteID, Signature: signature, Destination: d.Destination, Balance: "0"}, nil
}

// recoverFunding resolves unfinished funding from the chain without the user's
// keypair: it installs a deposit that landed, completes a close that landed, and
// re-sends transactions that were already signed. A step that needs the keypair
// returns errKeypairRequired and leaves the journal untouched.
func (w *SolanaWallet) recoverFunding(ctx context.Context) error {
	if w.funder == nil {
		return nil
	}
	file := w.snapshot()
	if file.Deposit == nil && file.Withdrawal == nil {
		return nil
	}
	// What the chain says decides what happens next, so first make sure this RPC is the pinned deployment.
	if _, err := w.VerifyChain(ctx); err != nil {
		return err
	}
	switch {
	case file.Deposit != nil:
		_, err := w.driveDeposit(ctx, "")
		return err
	case file.Withdrawal != nil:
		_, err := w.driveWithdrawal(ctx, "")
		return err
	}
	return nil
}

func operationID(operation json.RawMessage) string {
	var parsed struct {
		ID string `json:"operation_id"`
	}
	_ = json.Unmarshal(operation, &parsed)
	return parsed.ID
}

// lastSignature is the final (executing) transaction's signature of a signed operation.
func lastSignature(signed json.RawMessage) string {
	var parsed struct {
		Transactions []struct {
			Signature string `json:"signature"`
		} `json:"transactions"`
	}
	if json.Unmarshal(signed, &parsed) != nil || len(parsed.Transactions) == 0 {
		return ""
	}
	return parsed.Transactions[len(parsed.Transactions)-1].Signature
}

func commas(value uint64) string {
	text := fmt.Sprint(value)
	var out bytes.Buffer
	for i, digit := range text {
		if i > 0 && (len(text)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(digit)
	}
	return out.String()
}

// solText renders lamports as a decimal SOL amount.
func solText(lamports uint64) string {
	whole, fraction := lamports/lamportsPerSOL, fmt.Sprintf("%09d", lamports%lamportsPerSOL)
	for len(fraction) > 1 && fraction[len(fraction)-1] == '0' {
		fraction = fraction[:len(fraction)-1]
	}
	return fmt.Sprintf("%d.%s", whole, fraction)
}
