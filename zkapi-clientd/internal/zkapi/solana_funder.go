package zkapi

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// SolanaDepositParams is a fresh note secret and its on-chain registration
// commitment. The secret is the only thing that can ever spend the note.
type SolanaDepositParams struct {
	Secret     string `json:"secret"`
	Commitment string `json:"registration_commitment"`
}

// SolanaTxState is how far one signed transaction got on chain.
type SolanaTxState struct {
	Signature string `json:"signature"`
	Progress  string `json:"progress"` // unknown, processed, confirmed or finalized
	Failed    bool   `json:"failed"`
}

// SolanaSignedStatus summarises a signed operation. Expired means a transaction
// that never landed can no longer land: its blockhash is gone at finalized depth.
type SolanaSignedStatus struct {
	Transactions []SolanaTxState `json:"transactions"`
	Expired      bool            `json:"expired"`
}

func (s SolanaSignedStatus) allFinalized() bool {
	for _, tx := range s.Transactions {
		if tx.Progress != "finalized" || tx.Failed {
			return false
		}
	}
	return len(s.Transactions) > 0
}

func (s SolanaSignedStatus) anyFailed() bool {
	for _, tx := range s.Transactions {
		if tx.Failed && tx.Progress == "finalized" {
			return true
		}
	}
	return false
}

// SolanaNoteInfo is the vault's finalized note account.
type SolanaNoteInfo struct {
	Exists     bool   `json:"exists"`
	Commitment string `json:"commitment"`
	Amount     uint64 `json:"amount"`
	Expiry     uint64 `json:"expiry"`
	Active     bool   `json:"active"`
}

// SolanaWithdrawInput is what the helper needs to prove a mutual close.
type SolanaWithdrawInput struct {
	Destination string
	Snapshot    json.RawMessage // finalized whole-tree snapshot from the indexer
	NoteID      uint32
	Clearance   json.RawMessage // the server's signed clearance for this note's withdrawal nullifier
}

// SolanaFunder is the wallet helper's funding surface: vault transactions and
// the proofs behind them. Go owns durable state and decides what happens next;
// every transaction is built, checked and signed by the Rust helper, and a
// signed operation can be re-submitted any number of times (idempotent).
type SolanaFunder interface {
	WalletConfig(ctx context.Context, pin config.Solana) (json.RawMessage, error)
	KeypairPubkey(ctx context.Context, keypairPath string) (string, error)
	DepositParams(ctx context.Context) (SolanaDepositParams, error)
	PrepareDeposit(ctx context.Context, payer, commitment string, amount uint64) (noteID uint32, operation json.RawMessage, err error)
	ConfirmDeposit(ctx context.Context, walletConfig json.RawMessage, secret string, noteID uint32, amount, expiry uint64) (state json.RawMessage, err error)
	WithdrawalNullifier(ctx context.Context, walletConfig, state json.RawMessage) (string, error)
	ProveWithdrawal(ctx context.Context, walletConfig, state json.RawMessage, in SolanaWithdrawInput) (plan json.RawMessage, err error)
	PrepareWithdrawal(ctx context.Context, payer, destination string, plan json.RawMessage) (operation json.RawMessage, err error)
	PrepareCancel(ctx context.Context, payer, operationID string) (operation json.RawMessage, err error)
	SignOperation(ctx context.Context, keypairPath string, operation json.RawMessage) (signed json.RawMessage, err error)
	SubmitSigned(ctx context.Context, signed json.RawMessage, finalize bool) (signatures []string, err error)
	SignedStatus(ctx context.Context, signed json.RawMessage) (SolanaSignedStatus, error)
	NoteStatus(ctx context.Context, noteID uint32) (SolanaNoteInfo, error)
	NullifierUsed(ctx context.Context, nullifier string) (bool, error)
}

// Helper refusals a funding flow acts on. Anything else is an unknown outcome.
const (
	helperStaleRoot      = "stale_root"
	helperStaleNote      = "stale_note_id"
	helperBlockhash      = "blockhash_expired"
	helperTransactionBad = "transaction_failed"
)

// session starts the helper, optionally pointing it at the pinned chain.
func (p ExecSolanaProver) session(ctx context.Context, chain bool) (*proverSession, func(), error) {
	session, cancel, err := p.start(ctx)
	if err != nil {
		return nil, nil, err
	}
	done := func() {
		session.close()
		cancel()
	}
	if chain {
		if err := session.connect(); err != nil {
			done()
			return nil, nil, err
		}
	}
	return session, done, nil
}

func (p ExecSolanaProver) WalletConfig(ctx context.Context, pin config.Solana) (json.RawMessage, error) {
	session, done, err := p.session(ctx, false)
	if err != nil {
		return nil, err
	}
	defer done()
	return session.call("wallet_config", map[string]any{
		"program_id": pin.ProgramID, "vault_state": pin.VaultState, "genesis_hash": pin.GenesisHash,
		"state_signing_key": pin.StateSigningKey, "clearance_signing_key": pin.ClearanceSigningKey, "request_charge_cap": pin.MinLeaseCredits,
	})
}

func (p ExecSolanaProver) KeypairPubkey(ctx context.Context, keypairPath string) (string, error) {
	session, done, err := p.session(ctx, false)
	if err != nil {
		return "", err
	}
	defer done()
	raw, err := session.call("keypair_pubkey", map[string]any{"keypair": keypairPath})
	if err != nil {
		return "", err
	}
	var reply struct {
		Pubkey string `json:"pubkey"`
	}
	if json.Unmarshal(raw, &reply) != nil || !config.Base58Account(reply.Pubkey) {
		return "", &Error{502, "solana_prover_failed"}
	}
	return reply.Pubkey, nil
}

func (p ExecSolanaProver) DepositParams(ctx context.Context) (SolanaDepositParams, error) {
	session, done, err := p.session(ctx, false)
	if err != nil {
		return SolanaDepositParams{}, err
	}
	defer done()
	raw, err := session.call("deposit_params", nil)
	if err != nil {
		return SolanaDepositParams{}, err
	}
	var params SolanaDepositParams
	if json.Unmarshal(raw, &params) != nil || params.Secret == "" || params.Commitment == "" {
		return SolanaDepositParams{}, &Error{502, "solana_prover_failed"}
	}
	return params, nil
}

func (p ExecSolanaProver) PrepareDeposit(ctx context.Context, payer, commitment string, amount uint64) (uint32, json.RawMessage, error) {
	session, done, err := p.session(ctx, true)
	if err != nil {
		return 0, nil, err
	}
	defer done()
	raw, err := session.call("deposit_prepare", map[string]any{"payer": payer, "commitment": commitment, "amount": amount})
	if err != nil {
		return 0, nil, err
	}
	var reply struct {
		NoteID    uint32          `json:"note_id"`
		Operation json.RawMessage `json:"operation"`
	}
	if json.Unmarshal(raw, &reply) != nil || len(reply.Operation) == 0 {
		return 0, nil, &Error{502, "solana_prover_failed"}
	}
	return reply.NoteID, reply.Operation, nil
}

// walletSession loads the stored wallet into a helper session.
func (p ExecSolanaProver) walletSession(ctx context.Context, chain bool, walletConfig, state json.RawMessage) (*proverSession, func(), error) {
	session, done, err := p.session(ctx, chain)
	if err != nil {
		return nil, nil, err
	}
	if len(state) == 0 {
		state = json.RawMessage("null")
	}
	if _, err := session.call("load_wallet", map[string]any{"config": walletConfig, "state": state, "journal": nil}); err != nil {
		done()
		return nil, nil, err
	}
	return session, done, nil
}

func (p ExecSolanaProver) ConfirmDeposit(ctx context.Context, walletConfig json.RawMessage, secret string, noteID uint32, amount, expiry uint64) (json.RawMessage, error) {
	session, done, err := p.walletSession(ctx, false, walletConfig, nil)
	if err != nil {
		return nil, err
	}
	defer done()
	raw, err := session.call("deposit_confirm", map[string]any{"secret": secret, "note_id": noteID, "amount": amount, "expiry_ts": expiry})
	if err != nil {
		return nil, err
	}
	var reply struct {
		State json.RawMessage `json:"state"`
	}
	if json.Unmarshal(raw, &reply) != nil || len(reply.State) == 0 || bytes.Equal(reply.State, []byte("null")) {
		return nil, &Error{502, "solana_prover_failed"}
	}
	return reply.State, nil
}

func (p ExecSolanaProver) WithdrawalNullifier(ctx context.Context, walletConfig, state json.RawMessage) (string, error) {
	session, done, err := p.walletSession(ctx, false, walletConfig, state)
	if err != nil {
		return "", err
	}
	defer done()
	raw, err := session.call("withdrawal_nullifier", nil)
	if err != nil {
		return "", err
	}
	var reply struct {
		Nullifier string `json:"nullifier"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.Nullifier == "" {
		return "", &Error{502, "solana_prover_failed"}
	}
	return reply.Nullifier, nil
}

func (p ExecSolanaProver) ProveWithdrawal(ctx context.Context, walletConfig, state json.RawMessage, in SolanaWithdrawInput) (json.RawMessage, error) {
	session, done, err := p.walletSession(ctx, false, walletConfig, state)
	if err != nil {
		return nil, err
	}
	defer done()
	rawPath, err := session.call("tree_path", map[string]any{"args": map[string]any{"snapshot": in.Snapshot, "note_id": in.NoteID, "require_existing": true}})
	if err != nil {
		return nil, err
	}
	var path struct {
		ActiveRoot json.RawMessage `json:"active_root"`
		Siblings   json.RawMessage `json:"siblings"`
	}
	if json.Unmarshal(rawPath, &path) != nil {
		return nil, &Error{502, "solana_prover_failed"}
	}
	plan, err := session.call("withdraw_prove", map[string]any{"args": map[string]any{
		"destination": in.Destination, "active_root": path.ActiveRoot, "merkle_siblings": path.Siblings, "clearance": in.Clearance,
	}})
	if err != nil {
		return nil, err
	}
	return plan, nil
}

func (p ExecSolanaProver) operation(ctx context.Context, command string, fields map[string]any) (json.RawMessage, error) {
	session, done, err := p.session(ctx, true)
	if err != nil {
		return nil, err
	}
	defer done()
	raw, err := session.call(command, fields)
	if err != nil {
		return nil, err
	}
	var reply struct {
		Operation json.RawMessage `json:"operation"`
	}
	if json.Unmarshal(raw, &reply) != nil || len(reply.Operation) == 0 {
		return nil, &Error{502, "solana_prover_failed"}
	}
	return reply.Operation, nil
}

func (p ExecSolanaProver) PrepareWithdrawal(ctx context.Context, payer, destination string, plan json.RawMessage) (json.RawMessage, error) {
	return p.operation(ctx, "withdraw_prepare", map[string]any{"payer": payer, "destination": destination, "plan": plan})
}

func (p ExecSolanaProver) PrepareCancel(ctx context.Context, payer, operationID string) (json.RawMessage, error) {
	return p.operation(ctx, "cancel_prepare", map[string]any{"payer": payer, "operation_id": operationID})
}

func (p ExecSolanaProver) SignOperation(ctx context.Context, keypairPath string, operation json.RawMessage) (json.RawMessage, error) {
	session, done, err := p.session(ctx, true)
	if err != nil {
		return nil, err
	}
	defer done()
	raw, err := session.call("sign_operation", map[string]any{"keypair": keypairPath, "operation": operation})
	if err != nil {
		return nil, err
	}
	var reply struct {
		Signed json.RawMessage `json:"signed"`
	}
	if json.Unmarshal(raw, &reply) != nil || len(reply.Signed) == 0 {
		return nil, &Error{502, "solana_prover_failed"}
	}
	return reply.Signed, nil
}

func (p ExecSolanaProver) SubmitSigned(ctx context.Context, signed json.RawMessage, finalize bool) ([]string, error) {
	session, done, err := p.session(ctx, true)
	if err != nil {
		return nil, err
	}
	defer done()
	raw, err := session.call("submit_signed", map[string]any{"signed": signed, "finalize": finalize})
	if err != nil {
		return nil, err
	}
	var reply struct {
		Signatures []string `json:"signatures"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return nil, &Error{502, "solana_prover_failed"}
	}
	return reply.Signatures, nil
}

func (p ExecSolanaProver) SignedStatus(ctx context.Context, signed json.RawMessage) (SolanaSignedStatus, error) {
	session, done, err := p.session(ctx, true)
	if err != nil {
		return SolanaSignedStatus{}, err
	}
	defer done()
	raw, err := session.call("signed_status", map[string]any{"signed": signed})
	if err != nil {
		return SolanaSignedStatus{}, err
	}
	var status SolanaSignedStatus
	if json.Unmarshal(raw, &status) != nil {
		return SolanaSignedStatus{}, &Error{502, "solana_prover_failed"}
	}
	return status, nil
}

func (p ExecSolanaProver) NoteStatus(ctx context.Context, noteID uint32) (SolanaNoteInfo, error) {
	session, done, err := p.session(ctx, true)
	if err != nil {
		return SolanaNoteInfo{}, err
	}
	defer done()
	raw, err := session.call("note_status", map[string]any{"note_id": noteID})
	if err != nil {
		return SolanaNoteInfo{}, err
	}
	var note SolanaNoteInfo
	if json.Unmarshal(raw, &note) != nil {
		return SolanaNoteInfo{}, &Error{502, "solana_prover_failed"}
	}
	return note, nil
}

func (p ExecSolanaProver) NullifierUsed(ctx context.Context, nullifier string) (bool, error) {
	session, done, err := p.session(ctx, true)
	if err != nil {
		return false, err
	}
	defer done()
	raw, err := session.call("nullifier_status", map[string]any{"nullifier": nullifier})
	if err != nil {
		return false, err
	}
	var reply struct {
		Used bool `json:"used"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return false, &Error{502, "solana_prover_failed"}
	}
	return reply.Used, nil
}
