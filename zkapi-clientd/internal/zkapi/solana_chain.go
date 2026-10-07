package zkapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// The vault program's Anchor account layout, as the browser SDK decodes it
// (sdk/services/zkapiNativeSol.mjs: decodeSolanaVaultState).
const (
	upgradeableLoader  = "BPFLoaderUpgradeab1e11111111111111111111111"
	vaultStateLength   = 343
	vaultVersion       = 1
	maxChainReplyBytes = 1 << 20
)

var vaultDiscriminator = []byte{228, 196, 82, 165, 98, 210, 235, 152}

// SolanaVault is the verified on-chain identity and configuration of the pinned vault.
type SolanaVault struct {
	Authority                    string
	Treasury                     string
	NextNoteID                   uint32
	RequestChargeCap             uint64
	NoteTTLSeconds               uint64
	ChallengePeriod              uint64
	TotalCredits                 uint64
	StateKeyX, StateKeyY         string
	ClearanceKeyX, ClearanceKeyY string
}

// ChainMismatchError is a pinned-deployment check that failed against the chain.
// Its text names what differs; it never carries wallet material.
type ChainMismatchError struct{ Reason string }

func (e *ChainMismatchError) Error() string {
	return "on-chain verification failed: " + e.Reason + "; refusing to use this deployment"
}

func mismatch(format string, args ...any) error {
	return &ChainMismatchError{Reason: fmt.Sprintf(format, args...)}
}

type chainAccount struct {
	Owner      string
	Executable bool
	Data       []byte
	Lamports   uint64
}

// solanaRPC is a minimal read-only JSON-RPC client over the (relay-aware) HTTP client.
type solanaRPC struct {
	http *http.Client
	url  string
	id   int
}

func (r *solanaRPC) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	r.id++
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := r.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{http.StatusBadGateway, "solana_rpc_unavailable"}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxChainReplyBytes+1))
	if err != nil || len(data) > maxChainReplyBytes || response.StatusCode != http.StatusOK {
		return nil, &Error{http.StatusBadGateway, "solana_rpc_unavailable"}
	}
	var reply struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &reply) != nil || len(reply.Error) != 0 && !bytes.Equal(reply.Error, []byte("null")) || len(reply.Result) == 0 {
		return nil, &Error{http.StatusBadGateway, "solana_rpc_rejected_" + method}
	}
	return reply.Result, nil
}

func (r *solanaRPC) genesisHash(ctx context.Context) (string, error) {
	raw, err := r.call(ctx, "getGenesisHash")
	if err != nil {
		return "", err
	}
	var hash string
	if json.Unmarshal(raw, &hash) != nil || hash == "" {
		return "", &Error{http.StatusBadGateway, "invalid_solana_rpc_response"}
	}
	return hash, nil
}

// account reads one account at finalized commitment; nil means it does not exist.
func (r *solanaRPC) account(ctx context.Context, address string) (*chainAccount, error) {
	raw, err := r.call(ctx, "getAccountInfo", address, map[string]any{"commitment": "finalized", "encoding": "base64"})
	if err != nil {
		return nil, err
	}
	var reply struct {
		Value *struct {
			Owner      string   `json:"owner"`
			Executable bool     `json:"executable"`
			Lamports   uint64   `json:"lamports"`
			Data       []string `json:"data"`
		} `json:"value"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return nil, &Error{http.StatusBadGateway, "invalid_solana_rpc_response"}
	}
	if reply.Value == nil {
		return nil, nil
	}
	if len(reply.Value.Data) != 2 || reply.Value.Data[1] != "base64" {
		return nil, mismatch("the RPC did not return canonical base64 data for %s", address)
	}
	data, err := base64.StdEncoding.DecodeString(reply.Value.Data[0])
	if err != nil {
		return nil, mismatch("the RPC returned malformed data for %s", address)
	}
	return &chainAccount{Owner: reply.Value.Owner, Executable: reply.Value.Executable, Data: data, Lamports: reply.Value.Lamports}, nil
}

// balance returns an address's lamports at confirmed commitment (0 when absent).
func (r *solanaRPC) balance(ctx context.Context, address string) (uint64, error) {
	raw, err := r.call(ctx, "getBalance", address, map[string]any{"commitment": "confirmed"})
	if err != nil {
		return 0, err
	}
	var reply struct {
		Value uint64 `json:"value"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return 0, &Error{http.StatusBadGateway, "invalid_solana_rpc_response"}
	}
	return reply.Value, nil
}

func felt32(data []byte) string { return "0x" + fmt.Sprintf("%x", data) }

func decodeVault(data []byte) (state SolanaVault, version byte, paused bool, genesis string, chainID string, binding string, err error) {
	if len(data) != vaultStateLength || !bytes.Equal(data[:8], vaultDiscriminator) {
		return state, 0, false, "", "", "", mismatch("the vault account does not have the vault program's canonical layout")
	}
	state = SolanaVault{
		Authority: config.Base58Encode(data[11:43]), Treasury: config.Base58Encode(data[43:75]),
		NextNoteID:       binary.LittleEndian.Uint32(data[179:183]),
		NoteTTLSeconds:   binary.LittleEndian.Uint64(data[183:191]),
		ChallengePeriod:  binary.LittleEndian.Uint64(data[191:199]),
		RequestChargeCap: binary.LittleEndian.Uint64(data[199:207]),
		TotalCredits:     binary.LittleEndian.Uint64(data[207:215]),
		StateKeyX:        felt32(data[215:247]), StateKeyY: felt32(data[247:279]),
		ClearanceKeyX: felt32(data[279:311]), ClearanceKeyY: felt32(data[311:343]),
	}
	chain := new(big.Int).SetUint64(binary.LittleEndian.Uint64(data[107:115]))
	return state, data[8], data[10] != 0, config.Base58Encode(data[75:107]), chain.String(), felt32(data[115:147]), nil
}

// VerifySolanaChain checks the pinned deployment against the chain, reading at
// finalized commitment through the pinned RPC. It mirrors the browser SDK's
// assertSolanaVault and adds the vault's signing keys and request cap:
//
//   - the RPC is on the pinned cluster (genesis hash), before and after the reads;
//   - the vault state account exists, is owned by the pinned program, and holds
//     the program's canonical vault layout with the pinned identity (genesis,
//     chain ID, protocol binding), is not paused, and carries the pinned
//     state/clearance signing keys and per-request cap;
//   - the program account is an executable loader-v3 program whose program-data
//     account has no upgrade authority, so the code can never change.
//
// Any difference is an error naming what differs.
func VerifySolanaChain(ctx context.Context, client *http.Client, pin config.Solana) (SolanaVault, error) {
	rpc := &solanaRPC{http: client, url: pin.RPCURL}
	return verifySolanaChain(ctx, rpc, pin)
}

func verifySolanaChain(ctx context.Context, rpc *solanaRPC, pin config.Solana) (SolanaVault, error) {
	genesis, err := rpc.genesisHash(ctx)
	if err != nil {
		return SolanaVault{}, err
	}
	if genesis != pin.GenesisHash {
		return SolanaVault{}, mismatch("the RPC is on cluster %s, not the pinned genesis hash %s", short(genesis), short(pin.GenesisHash))
	}
	vault, err := rpc.account(ctx, pin.VaultState)
	if err != nil {
		return SolanaVault{}, err
	}
	if vault == nil {
		return SolanaVault{}, mismatch("the pinned vault %s does not exist on this cluster", short(pin.VaultState))
	}
	if vault.Owner != pin.ProgramID || vault.Executable {
		return SolanaVault{}, mismatch("the pinned vault %s is owned by %s, not the pinned program %s", short(pin.VaultState), short(vault.Owner), short(pin.ProgramID))
	}
	state, version, paused, vaultGenesis, chainID, binding, err := decodeVault(vault.Data)
	if err != nil {
		return SolanaVault{}, err
	}
	if version != vaultVersion || paused {
		return SolanaVault{}, mismatch("the vault is paused or has an unsupported version (%d)", version)
	}
	if vaultGenesis != pin.GenesisHash || chainID != pin.ChainID || !config.SameFelt(binding, pin.ProtocolBinding) {
		return SolanaVault{}, mismatch("the vault's own genesis hash, chain ID or protocol binding differs from the pins")
	}
	same := config.SameFelt
	if !same(state.StateKeyX, pin.StateSigningKey.X) || !same(state.StateKeyY, pin.StateSigningKey.Y) {
		return SolanaVault{}, mismatch("the vault's state signing key differs from the pinned key")
	}
	if !same(state.ClearanceKeyX, pin.ClearanceSigningKey.X) || !same(state.ClearanceKeyY, pin.ClearanceSigningKey.Y) {
		return SolanaVault{}, mismatch("the vault's clearance signing key differs from the pinned key")
	}
	if state.RequestChargeCap != pin.MinLeaseCredits {
		return SolanaVault{}, mismatch("the vault's per-request cap is %d lamports, the pin says %d", state.RequestChargeCap, pin.MinLeaseCredits)
	}
	program, err := rpc.account(ctx, pin.ProgramID)
	if err != nil {
		return SolanaVault{}, err
	}
	if program == nil {
		return SolanaVault{}, mismatch("the pinned program %s does not exist on this cluster", short(pin.ProgramID))
	}
	if program.Owner != upgradeableLoader || !program.Executable || len(program.Data) != 36 || binary.LittleEndian.Uint32(program.Data) != 2 {
		return SolanaVault{}, mismatch("the pinned program %s is not an executable loader-v3 program", short(pin.ProgramID))
	}
	programData, err := rpc.account(ctx, config.Base58Encode(program.Data[4:36]))
	if err != nil {
		return SolanaVault{}, err
	}
	if programData == nil || programData.Owner != upgradeableLoader || programData.Executable || len(programData.Data) < 13 || binary.LittleEndian.Uint32(programData.Data) != 3 {
		return SolanaVault{}, mismatch("the pinned program's program-data account is missing or malformed")
	}
	if programData.Data[12] != 0 {
		return SolanaVault{}, mismatch("the pinned program %s can still be upgraded (its upgrade authority is not revoked)", short(pin.ProgramID))
	}
	again, err := rpc.genesisHash(ctx)
	if err != nil {
		return SolanaVault{}, err
	}
	if again != pin.GenesisHash {
		return SolanaVault{}, mismatch("the RPC changed cluster during verification")
	}
	return state, nil
}

func short(address string) string {
	if len(address) <= 12 {
		return address
	}
	return strings.Join([]string{address[:6], address[len(address)-4:]}, "...")
}
