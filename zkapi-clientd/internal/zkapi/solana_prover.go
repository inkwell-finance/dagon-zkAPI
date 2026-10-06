package zkapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// SolanaPrepareInput is everything the helper needs to turn the current note
// into one lease request proof. State and journal are secret-bearing.
type SolanaPrepareInput struct {
	Config          json.RawMessage // wallet config with request_charge_cap set to the lease budget
	State           json.RawMessage
	Snapshot        json.RawMessage // finalized whole-tree snapshot from the indexer
	NoteID          uint32
	Payload         string
	ClientRequestID string
	RequestTime     uint64
	CreatedAtMs     uint64
}

type SolanaPrepared struct {
	Request json.RawMessage
	Journal json.RawMessage
}

type SolanaCompleteInput struct {
	Config, State, Journal, Response json.RawMessage
}

// SolanaDerivation is the chain identity derived from public deployment pins.
type SolanaDerivation struct {
	ChainID         string `json:"chain_id"`
	ProtocolBinding string `json:"protocol_binding"`
}

// SolanaProver is the Solana wallet cryptography. The Go side owns durable
// state and the network protocol; every proof and state transition is computed
// by the same Rust code as the browser SDK, never reimplemented here.
type SolanaProver interface {
	Derive(ctx context.Context, programID, vaultState, genesisHash string) (SolanaDerivation, error)
	Prepare(ctx context.Context, in SolanaPrepareInput) (SolanaPrepared, error)
	Complete(ctx context.Context, in SolanaCompleteInput) (json.RawMessage, error)
}

// ExecSolanaProver runs the Solana wallet helper (the zkapi-serverd example
// solana_acceptance_wallet) once per operation. Secrets travel only over its
// stdin/stdout pipes; stderr is discarded and the environment is minimal.
type ExecSolanaProver struct {
	Binary   string
	SetupDir string
}

const proverTimeout = 15 * time.Minute

type proverSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	next   int
}

func (p ExecSolanaProver) start(ctx context.Context) (*proverSession, context.CancelFunc, error) {
	if p.Binary == "" || p.SetupDir == "" {
		return nil, nil, &Error{500, "solana_prover_not_configured"}
	}
	ctx, cancel := context.WithTimeout(ctx, proverTimeout)
	cmd := exec.CommandContext(ctx, p.Binary, p.SetupDir)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.WaitDelay = 5 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, &Error{500, "solana_prover_unavailable"}
	}
	return &proverSession{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 64<<10)}, cancel, nil
}

func (s *proverSession) close() {
	_ = s.stdin.Close()
	_ = s.cmd.Wait()
}

// call sends one command and returns the helper's result. Error text from the
// helper is dropped: it can echo protocol values.
func (s *proverSession) call(command string, fields map[string]any) (json.RawMessage, error) {
	s.next++
	body := map[string]any{"id": s.next, "command": command}
	for key, value := range fields {
		body[key] = value
	}
	line, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if _, err := s.stdin.Write(append(line, '\n')); err != nil {
		return nil, &Error{502, "solana_prover_failed"}
	}
	reply, err := s.readLine()
	if err != nil {
		return nil, &Error{502, "solana_prover_failed"}
	}
	var wire struct {
		ID     int             `json:"id"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(reply, &wire) != nil || wire.ID != s.next || !wire.OK {
		return nil, &Error{502, "solana_prover_rejected_" + command}
	}
	return wire.Result, nil
}

func (s *proverSession) readLine() ([]byte, error) {
	var line []byte
	for {
		part, isPrefix, err := s.stdout.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, part...)
		if len(line) > 32<<20 {
			return nil, errors.New("prover reply too large")
		}
		if !isPrefix {
			return line, nil
		}
	}
}

func (p ExecSolanaProver) Derive(ctx context.Context, programID, vaultState, genesisHash string) (SolanaDerivation, error) {
	session, cancel, err := p.start(ctx)
	if err != nil {
		return SolanaDerivation{}, err
	}
	defer cancel()
	defer session.close()
	raw, err := session.call("derive_deployment", map[string]any{"program_id": programID, "vault_state": vaultState, "genesis_hash": genesisHash})
	if err != nil {
		return SolanaDerivation{}, err
	}
	var derived SolanaDerivation
	if json.Unmarshal(raw, &derived) != nil || derived.ChainID == "" || derived.ProtocolBinding == "" {
		return SolanaDerivation{}, &Error{502, "solana_prover_failed"}
	}
	return derived, nil
}

func (p ExecSolanaProver) Prepare(ctx context.Context, in SolanaPrepareInput) (SolanaPrepared, error) {
	session, cancel, err := p.start(ctx)
	if err != nil {
		return SolanaPrepared{}, err
	}
	defer cancel()
	defer session.close()
	if _, err := session.call("load_wallet", map[string]any{"config": in.Config, "state": in.State, "journal": nil}); err != nil {
		return SolanaPrepared{}, err
	}
	rawPath, err := session.call("tree_path", map[string]any{"args": map[string]any{"snapshot": in.Snapshot, "note_id": in.NoteID, "require_existing": true}})
	if err != nil {
		return SolanaPrepared{}, err
	}
	var path struct {
		ActiveRoot json.RawMessage `json:"active_root"`
		Siblings   json.RawMessage `json:"siblings"`
	}
	if json.Unmarshal(rawPath, &path) != nil {
		return SolanaPrepared{}, &Error{502, "solana_prover_failed"}
	}
	raw, err := session.call("prepare_request", map[string]any{"args": map[string]any{
		"payload": in.Payload, "active_root": path.ActiveRoot, "merkle_siblings": path.Siblings,
		"client_request_id": in.ClientRequestID, "request_time": in.RequestTime, "created_at_ms": in.CreatedAtMs,
	}})
	if err != nil {
		return SolanaPrepared{}, err
	}
	var prepared struct {
		Request json.RawMessage `json:"request"`
		Journal json.RawMessage `json:"journal"`
	}
	if json.Unmarshal(raw, &prepared) != nil || len(prepared.Request) == 0 || len(prepared.Journal) == 0 || bytes.Equal(prepared.Journal, []byte("null")) {
		return SolanaPrepared{}, &Error{502, "solana_prover_failed"}
	}
	return SolanaPrepared{Request: prepared.Request, Journal: prepared.Journal}, nil
}

func (p ExecSolanaProver) Complete(ctx context.Context, in SolanaCompleteInput) (json.RawMessage, error) {
	session, cancel, err := p.start(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer session.close()
	if _, err := session.call("load_wallet", map[string]any{"config": in.Config, "state": in.State, "journal": in.Journal}); err != nil {
		return nil, err
	}
	if _, err := session.call("complete_response", map[string]any{"response": in.Response}); err != nil {
		return nil, err
	}
	raw, err := session.call("export_wallet", nil)
	if err != nil {
		return nil, err
	}
	var exported struct {
		State json.RawMessage `json:"state"`
	}
	if json.Unmarshal(raw, &exported) != nil || len(exported.State) == 0 || bytes.Equal(exported.State, []byte("null")) {
		return nil, &Error{502, "solana_prover_failed"}
	}
	return exported.State, nil
}
