// Package solanatest is a mock Solana JSON-RPC node for tests: a genesis hash, a
// table of accounts and balances, served over HTTP. It is imported only by tests.
package solanatest

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

const UpgradeableLoader = "BPFLoaderUpgradeab1e11111111111111111111111"

// Account is one on-chain account as getAccountInfo reports it.
type Account struct {
	Owner      string
	Executable bool
	Data       []byte
	Lamports   uint64
}

// Chain is a mock RPC node. Mutate Accounts and Balances under Lock.
type Chain struct {
	sync.Mutex
	Server   *httptest.Server
	Genesis  string
	Accounts map[string]Account
	Balances map[string]uint64
	Calls    []string
}

// New starts a mock node on the pinned cluster.
func New(t *testing.T, genesis string) *Chain {
	t.Helper()
	c := &Chain{Genesis: genesis, Accounts: map[string]Account{}, Balances: map[string]uint64{}}
	c.Server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.Server.Close)
	return c
}

func (c *Chain) serve(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c.Lock()
	defer c.Unlock()
	c.Calls = append(c.Calls, request.Method)
	reply := map[string]any{"jsonrpc": "2.0", "id": request.ID}
	address := func() string {
		var value string
		if len(request.Params) > 0 {
			_ = json.Unmarshal(request.Params[0], &value)
		}
		return value
	}
	switch request.Method {
	case "getGenesisHash":
		reply["result"] = c.Genesis
	case "getBalance":
		reply["result"] = map[string]any{"context": map[string]any{"slot": 1}, "value": c.Balances[address()]}
	case "getAccountInfo":
		account, ok := c.Accounts[address()]
		if !ok {
			reply["result"] = map[string]any{"context": map[string]any{"slot": 1}, "value": nil}
			break
		}
		reply["result"] = map[string]any{"context": map[string]any{"slot": 1}, "value": map[string]any{
			"owner": account.Owner, "executable": account.Executable, "lamports": account.Lamports,
			"data": []string{base64.StdEncoding.EncodeToString(account.Data), "base64"}, "rentEpoch": 0}}
	default:
		reply["error"] = map[string]any{"code": -32601, "message": "method not found"}
	}
	_ = json.NewEncoder(w).Encode(reply)
}

// Vault describes a vault account's contents; zero values are filled in by Data.
type Vault struct {
	Version          byte
	Paused           bool
	GenesisHash      string
	ChainID          uint64
	ProtocolBinding  string
	NextNoteID       uint32
	RequestChargeCap uint64
	StateKey         config.CurvePoint
	ClearanceKey     config.CurvePoint
}

func felt(value string) []byte {
	number, _ := new(big.Int).SetString(strings.TrimPrefix(value, "0x"), 16)
	out := make([]byte, 32)
	number.FillBytes(out)
	return out
}

// Data is the vault program's canonical account layout (343 bytes).
func (v Vault) Data() []byte {
	data := make([]byte, 343)
	copy(data, []byte{228, 196, 82, 165, 98, 210, 235, 152})
	data[8], data[10] = v.Version, 0
	if v.Paused {
		data[10] = 1
	}
	genesis, _ := config.Base58Decode(v.GenesisHash)
	copy(data[75:107], genesis)
	binary.LittleEndian.PutUint64(data[107:115], v.ChainID)
	copy(data[115:147], felt(v.ProtocolBinding))
	binary.LittleEndian.PutUint32(data[179:183], v.NextNoteID)
	binary.LittleEndian.PutUint64(data[199:207], v.RequestChargeCap)
	copy(data[215:247], felt(v.StateKey.X))
	copy(data[247:279], felt(v.StateKey.Y))
	copy(data[279:311], felt(v.ClearanceKey.X))
	copy(data[311:343], felt(v.ClearanceKey.Y))
	return data
}

// VaultFor is the vault a correct deployment of pin would hold.
func VaultFor(pin config.Solana) Vault {
	chainID, _ := new(big.Int).SetString(pin.ChainID, 10)
	return Vault{Version: 1, GenesisHash: pin.GenesisHash, ChainID: chainID.Uint64(), ProtocolBinding: pin.ProtocolBinding,
		RequestChargeCap: pin.MinLeaseCredits, StateKey: pin.StateSigningKey, ClearanceKey: pin.ClearanceSigningKey}
}

// ProgramDataAddress is the (fixed, arbitrary) address the mock gives the pinned program's code account.
func ProgramDataAddress(pin config.Solana) string {
	return config.Base58Encode([]byte("program-data-of-" + pin.ProgramID + "-padding-----")[:32])
}

// Install puts a correct, immutable deployment of pin on the chain.
func (c *Chain) Install(pin config.Solana) {
	c.Lock()
	defer c.Unlock()
	programData, _ := config.Base58Decode(ProgramDataAddress(pin))
	program := make([]byte, 36)
	binary.LittleEndian.PutUint32(program, 2)
	copy(program[4:], programData)
	c.Accounts[pin.ProgramID] = Account{Owner: UpgradeableLoader, Executable: true, Data: program, Lamports: 1}
	c.Accounts[ProgramDataAddress(pin)] = Account{Owner: UpgradeableLoader, Data: ProgramDataAccount(false), Lamports: 1}
	c.Accounts[pin.VaultState] = Account{Owner: pin.ProgramID, Data: VaultFor(pin).Data(), Lamports: 1}
}

// ProgramDataAccount is a loader-v3 program-data account, with or without an upgrade authority.
func ProgramDataAccount(upgradeable bool) []byte {
	data := make([]byte, 45)
	binary.LittleEndian.PutUint32(data, 3)
	if upgradeable {
		data[12] = 1
	}
	return data
}
