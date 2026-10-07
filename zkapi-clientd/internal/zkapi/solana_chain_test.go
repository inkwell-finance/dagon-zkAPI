package zkapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/solanatest"
)

func chainFixture(t *testing.T) (*solanatest.Chain, config.Solana) {
	t.Helper()
	chain := solanatest.New(t, testPin("").GenesisHash)
	pin := testPin("http://127.0.0.1:1")
	pin.RPCURL = chain.Server.URL
	chain.Install(pin)
	return chain, pin
}

func TestVerifySolanaChainAcceptsACorrectImmutableDeployment(t *testing.T) {
	chain, pin := chainFixture(t)
	vault, err := VerifySolanaChain(context.Background(), chain.Server.Client(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if vault.RequestChargeCap != pin.MinLeaseCredits || vault.NextNoteID != 0 {
		t.Fatalf("vault view: %+v", vault)
	}
}

func TestVerifySolanaChainRefusesEveryMismatchWithAClearError(t *testing.T) {
	setVault := func(chain *solanatest.Chain, pin config.Solana, mutate func(*solanatest.Vault)) {
		vault := solanatest.VaultFor(pin)
		mutate(&vault)
		chain.Accounts[pin.VaultState] = solanatest.Account{Owner: pin.ProgramID, Data: vault.Data()}
	}
	tests := map[string]struct {
		tamper func(*solanatest.Chain, *config.Solana)
		want   string
	}{
		"rpc on another cluster": {func(c *solanatest.Chain, _ *config.Solana) {
			c.Genesis = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
		}, "pinned genesis hash"},
		"vault missing": {func(c *solanatest.Chain, p *config.Solana) { delete(c.Accounts, p.VaultState) }, "does not exist"},
		"vault owned by another program": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[p.VaultState]
			account.Owner = config.PythReceiverProgram
			c.Accounts[p.VaultState] = account
		}, "not the pinned program"},
		"vault is executable": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[p.VaultState]
			account.Executable = true
			c.Accounts[p.VaultState] = account
		}, "not the pinned program"},
		"vault layout": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[p.VaultState]
			account.Data = account.Data[:300]
			c.Accounts[p.VaultState] = account
		}, "canonical layout"},
		"vault discriminator": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[p.VaultState]
			account.Data = append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, account.Data[8:]...)
			c.Accounts[p.VaultState] = account
		}, "canonical layout"},
		"vault version": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.Version = 2 })
		}, "unsupported version"},
		"vault paused": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.Paused = true })
		}, "paused"},
		"vault chain id": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.ChainID++ })
		}, "chain ID or protocol binding"},
		"vault binding": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.ProtocolBinding = "0x1234" })
		}, "chain ID or protocol binding"},
		"vault genesis": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.GenesisHash = config.PythReceiverProgram })
		}, "genesis hash, chain ID"},
		"state key": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.StateKey.X = "0x99" })
		}, "state signing key"},
		"state key y": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.StateKey.Y = "0x99" })
		}, "state signing key"},
		"clearance key": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.ClearanceKey.X = "0x99" })
		}, "clearance signing key"},
		"clearance key y": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.ClearanceKey.Y = "0x99" })
		}, "clearance signing key"},
		"request cap": {func(c *solanatest.Chain, p *config.Solana) {
			setVault(c, *p, func(v *solanatest.Vault) { v.RequestChargeCap++ })
		}, "per-request cap"},
		"program missing": {func(c *solanatest.Chain, p *config.Solana) { delete(c.Accounts, p.ProgramID) }, "does not exist"},
		"program not executable": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[p.ProgramID]
			account.Executable = false
			c.Accounts[p.ProgramID] = account
		}, "not an executable loader-v3"},
		"program owned by the legacy loader": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[p.ProgramID]
			account.Owner = "BPFLoader2111111111111111111111111111111111"
			c.Accounts[p.ProgramID] = account
		}, "not an executable loader-v3"},
		"program account truncated": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[p.ProgramID]
			account.Data = account.Data[:20]
			c.Accounts[p.ProgramID] = account
		}, "not an executable loader-v3"},
		"program data missing": {func(c *solanatest.Chain, p *config.Solana) { delete(c.Accounts, solanatest.ProgramDataAddress(*p)) }, "program-data account is missing"},
		"program data wrong owner": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[solanatest.ProgramDataAddress(*p)]
			account.Owner = config.PythReceiverProgram
			c.Accounts[solanatest.ProgramDataAddress(*p)] = account
		}, "program-data account is missing or malformed"},
		"program data truncated": {func(c *solanatest.Chain, p *config.Solana) {
			account := c.Accounts[solanatest.ProgramDataAddress(*p)]
			account.Data = account.Data[:8]
			c.Accounts[solanatest.ProgramDataAddress(*p)] = account
		}, "program-data account is missing or malformed"},
		"upgrade authority present": {func(c *solanatest.Chain, p *config.Solana) {
			c.Accounts[solanatest.ProgramDataAddress(*p)] = solanatest.Account{Owner: solanatest.UpgradeableLoader, Data: solanatest.ProgramDataAccount(true)}
		}, "can still be upgraded"},
		"a different program is pinned": {func(c *solanatest.Chain, p *config.Solana) { p.ProgramID = config.PythReceiverProgram }, "not the pinned program"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chain, pin := chainFixture(t)
			chain.Lock()
			test.tamper(chain, &pin)
			chain.Unlock()
			_, err := VerifySolanaChain(context.Background(), chain.Server.Client(), pin)
			var refusal *ChainMismatchError
			if !errors.As(err, &refusal) {
				t.Fatalf("not refused with a chain mismatch: %v", err)
			}
			if !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "refusing to use this deployment") {
				t.Fatalf("error %q does not say %q", err, test.want)
			}
		})
	}
}

func TestVerifySolanaChainReportsAnUnreachableOrBrokenRPC(t *testing.T) {
	_, pin := chainFixture(t)
	pin.RPCURL = "http://127.0.0.1:1"
	if _, err := VerifySolanaChain(context.Background(), http.DefaultClient, pin); err == nil || errors.As(err, new(*ChainMismatchError)) {
		t.Fatalf("an unreachable RPC is an availability error, not a mismatch: %v", err)
	}
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is unhealthy"}}`))
	}))
	defer broken.Close()
	pin.RPCURL = broken.URL
	if _, err := VerifySolanaChain(context.Background(), broken.Client(), pin); err == nil || errors.As(err, new(*ChainMismatchError)) {
		t.Fatalf("an RPC error is not a verified deployment: %v", err)
	}
}

func TestVerifySolanaChainRefusesAClusterThatChangesBetweenReads(t *testing.T) {
	chain, pin := chainFixture(t)
	calls := 0
	flipping := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		if strings.Contains(string(body[:n]), "getGenesisHash") {
			calls++
			if calls > 1 {
				chain.Lock()
				chain.Genesis = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
				chain.Unlock()
			}
		}
		// Forward to the real mock.
		forward, _ := http.NewRequest(http.MethodPost, chain.Server.URL, strings.NewReader(string(body[:n])))
		forward.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(forward)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		reply := make([]byte, 1<<16)
		m, _ := response.Body.Read(reply)
		_, _ = w.Write(reply[:m])
	}))
	defer flipping.Close()
	pin.RPCURL = flipping.URL
	if _, err := VerifySolanaChain(context.Background(), flipping.Client(), pin); err == nil || !strings.Contains(err.Error(), "changed cluster") {
		t.Fatalf("a cluster that changes during verification must be refused: %v", err)
	}
}

func TestVaultLayoutOffsetsMatchTheBrowserSDKDecoder(t *testing.T) {
	// The same offsets as sdk/services/zkapiNativeSol.mjs decodeSolanaVaultState: a field written at an
	// SDK offset must read back from this decoder.
	vault := solanatest.Vault{Version: 1, GenesisHash: config.PythReceiverProgram, ChainID: 0x1122334455667788, ProtocolBinding: "0xabcdef", NextNoteID: 7,
		RequestChargeCap: 12_000_000, StateKey: config.CurvePoint{X: "0x01", Y: "0x02"}, ClearanceKey: config.CurvePoint{X: "0x03", Y: "0x04"}}
	state, version, paused, genesis, chainID, binding, err := decodeVault(vault.Data())
	if err != nil || version != 1 || paused || genesis != config.PythReceiverProgram || chainID != "1234605616436508552" || !config.SameFelt(binding, "0xabcdef") {
		t.Fatalf("decoded identity: %v %v %v %v %v %v", err, version, paused, genesis, chainID, binding)
	}
	if state.NextNoteID != 7 || state.RequestChargeCap != 12_000_000 || !config.SameFelt(state.StateKeyY, "0x02") || !config.SameFelt(state.ClearanceKeyX, "0x03") {
		t.Fatalf("decoded config: %+v", state)
	}
}
