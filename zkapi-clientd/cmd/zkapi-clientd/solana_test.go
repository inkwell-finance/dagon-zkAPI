package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/solanatest"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

const solanaTestBinding = "0x" + "bb00000000000000000000000000000000000000000000000000000000000002"

func solanaTestPin(rpc string) config.Solana {
	pin := config.Solana{
		ServerURL: "http://127.0.0.1:9", IndexerURL: "http://127.0.0.1:10", RPCURL: rpc, InferenceBase: "http://127.0.0.1:11/zk", Cluster: "localnet",
		ProgramID: "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H", VaultState: "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE",
		GenesisHash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", ChainID: "11235813213455891", ProtocolBinding: solanaTestBinding,
		StateSigningKey:     config.CurvePoint{X: "0x" + strings.Repeat("11", 32), Y: "0x" + strings.Repeat("12", 32)},
		ClearanceSigningKey: config.CurvePoint{X: "0x" + strings.Repeat("21", 32), Y: "0x" + strings.Repeat("22", 32)},
		MinLeaseCredits:     12000000,
	}
	return pin
}

// solanaTestChain is a mock Solana node holding a correct immutable deployment of solanaTestPin.
func solanaTestChain(t *testing.T) (*solanatest.Chain, config.Solana) {
	t.Helper()
	chain := solanatest.New(t, "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")
	pin := solanaTestPin(chain.Server.URL)
	chain.Install(pin)
	return chain, pin
}

func solanaDeploymentFile(t *testing.T, dir string, pin config.Solana) string {
	t.Helper()
	raw, _ := json.Marshal(pin)
	path := filepath.Join(dir, "deployment.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSolanaInitImportAndStatus(t *testing.T) {
	scratch := t.TempDir()
	dir := filepath.Join(scratch, "cfg")
	_, pin := solanaTestChain(t)
	deployment := solanaDeploymentFile(t, scratch, pin)
	var out bytes.Buffer
	if err := runSolana(context.Background(), dir, []string{"init", "--deployment", deployment}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Verified on chain") {
		t.Fatalf("init did not report its on-chain verification: %q", out.String())
	}
	c, err := config.Load(dir)
	if err != nil || c.ZKAPI.Network != config.SolanaNetwork || c.ZKAPI.Solana == nil || c.ZKAPI.Solana.PythMaxAgeSeconds != 60 || c.ZKAPI.Solana.PythPriceAccount == "" {
		t.Fatalf("saved profile: %+v err=%v", c.ZKAPI, err)
	}
	if err := runSolana(context.Background(), dir, []string{"init", "--deployment", deployment}, nil, &out); err == nil {
		t.Fatal("init overwrote an existing profile")
	}
	if err := runSolana(context.Background(), dir, []string{"status"}, nil, &out); err == nil {
		t.Fatal("status succeeded without a wallet")
	}
	wallet := `{"config":{"protocol_version":2,"ledger_backend":"dagon.solana.groth16.v1","chain_id":"11235813213455891","contract_address":"` + solanaTestBinding + `","request_charge_cap":12000000},
		"state":{"note_id":0,"chain_id":"11235813213455891","contract_address":"` + solanaTestBinding + `","current_balance":1000000000,"secret_s":"0xsecret"},"journal":null}`
	out.Reset()
	if err := runSolana(context.Background(), dir, []string{"import-wallet", "--file", "-"}, strings.NewReader(wallet), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "secret") && !strings.Contains(out.String(), "note secret") {
		t.Fatalf("import printed wallet material: %q", out.String())
	}
	if err := runSolana(context.Background(), dir, []string{"import-wallet", "--file", "-"}, strings.NewReader(wallet), &out); err == nil {
		t.Fatal("a second import replaced the wallet")
	}
	out.Reset()
	if err := runSolana(context.Background(), dir, []string{"status"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	var status struct {
		Wallet struct {
			HasNote bool   `json:"has_note"`
			Balance string `json:"private_balance_lamports"`
		} `json:"wallet"`
	}
	if json.Unmarshal(out.Bytes(), &status) != nil || !status.Wallet.HasNote || status.Wallet.Balance != "1000000000" || strings.Contains(out.String(), "0xsecret") {
		t.Fatalf("status output %q", out.String())
	}
}

func TestSolanaInitRejectsAMismatchedDeploymentAndUnknownFields(t *testing.T) {
	scratch := t.TempDir()
	_, pin := solanaTestChain(t)
	path := solanaDeploymentFile(t, scratch, pin)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(raw, []byte(`"cluster":"localnet"`), []byte(`"cluster":"localnet","surprise":1`), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runSolana(context.Background(), filepath.Join(scratch, "cfg"), []string{"init", "--deployment", path}, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown deployment field accepted")
	}
	if err := runSolana(context.Background(), filepath.Join(scratch, "cfg2"), []string{"bogus"}, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}

func TestLeaseControlRequiresConfirmation(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runLease(context.Background(), config.Config{}, []string{"settle"}, &out, &errOut)
	if err == nil {
		t.Fatal("settle ran without a running daemon")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%q", out.String())
	}
}

func TestSolanaInitVerifiesTheChainAndRefusesAMismatchWithoutSavingAnything(t *testing.T) {
	for name, tamper := range map[string]func(*solanatest.Chain, *config.Solana){
		"wrong program id pin": func(_ *solanatest.Chain, pin *config.Solana) {
			pin.ProgramID = "rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ"
		},
		"wrong vault pin": func(_ *solanatest.Chain, pin *config.Solana) { pin.VaultState = config.PythReceiverProgram },
		"wrong genesis pin": func(_ *solanatest.Chain, pin *config.Solana) {
			pin.GenesisHash = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
		},
		"upgradeable program": func(chain *solanatest.Chain, pin *config.Solana) {
			chain.Accounts[solanatest.ProgramDataAddress(*pin)] = solanatest.Account{Owner: solanatest.UpgradeableLoader, Data: solanatest.ProgramDataAccount(true)}
		},
		"paused vault": func(chain *solanatest.Chain, pin *config.Solana) {
			vault := solanatest.VaultFor(*pin)
			vault.Paused = true
			chain.Accounts[pin.VaultState] = solanatest.Account{Owner: pin.ProgramID, Data: vault.Data()}
		},
	} {
		t.Run(name, func(t *testing.T) {
			scratch := t.TempDir()
			chain, pin := solanaTestChain(t)
			tamper(chain, &pin)
			dir := filepath.Join(scratch, "cfg")
			err := runSolana(context.Background(), dir, []string{"init", "--deployment", solanaDeploymentFile(t, scratch, pin)}, nil, &bytes.Buffer{})
			var refusal *zkapi.ChainMismatchError
			if !errors.As(err, &refusal) {
				t.Fatalf("init was not refused with an on-chain verification error: %v", err)
			}
			if _, err := config.Load(dir); err == nil {
				t.Fatal("a refused init saved a profile")
			}
		})
	}
}

func TestSolanaVerifyReportsTheVault(t *testing.T) {
	scratch := t.TempDir()
	chain, pin := solanaTestChain(t)
	dir := filepath.Join(scratch, "cfg")
	if err := runSolana(context.Background(), dir, []string{"init", "--deployment", solanaDeploymentFile(t, scratch, pin)}, nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runSolana(context.Background(), dir, []string{"verify"}, nil, &out); err != nil || !strings.Contains(out.String(), `"verified": true`) {
		t.Fatalf("verify: %v %q", err, out.String())
	}
	// The program is upgraded behind the profile's back: verification now refuses.
	chain.Lock()
	chain.Accounts[solanatest.ProgramDataAddress(pin)] = solanatest.Account{Owner: solanatest.UpgradeableLoader, Data: solanatest.ProgramDataAccount(true)}
	chain.Unlock()
	if err := runSolana(context.Background(), dir, []string{"verify"}, nil, &out); err == nil || !strings.Contains(err.Error(), "can still be upgraded") {
		t.Fatalf("verify of an upgradeable program: %v", err)
	}
}

func TestSolanaInitRequiresAPinnedHelperAndExplainsHowToPinIt(t *testing.T) {
	scratch := t.TempDir()
	_, pin := solanaTestChain(t)
	helper := filepath.Join(scratch, "zkapi-solana-wallet")
	if err := os.WriteFile(helper, []byte("#!/bin/sh"+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	pin.Prover, pin.ProofSetupDir = helper, scratch
	err := runSolana(context.Background(), filepath.Join(scratch, "cfg"), []string{"init", "--deployment", solanaDeploymentFile(t, scratch, pin)}, nil, &bytes.Buffer{})
	digest, _ := zkapi.HashFile(helper)
	if err == nil || !strings.Contains(err.Error(), "--prover-sha256 "+digest) {
		t.Fatalf("an unpinned helper must be refused with its digest: %v", err)
	}
	// A pinned digest that is not the binary's is refused when the helper would run.
	pin.ProverSHA256 = strings.Repeat("0", 64)
	err = runSolana(context.Background(), filepath.Join(scratch, "cfg"), []string{"init", "--deployment", solanaDeploymentFile(t, scratch, pin)}, nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(fmt.Sprint(err), "solana_prover_hash_mismatch") {
		t.Fatalf("a mismatched pin must be refused: %v", err)
	}
}

func TestSolanaFundingCommandsNeedConfirmationAndValidArguments(t *testing.T) {
	scratch := t.TempDir()
	_, pin := solanaTestChain(t)
	dir := filepath.Join(scratch, "cfg")
	if err := runSolana(context.Background(), dir, []string{"init", "--deployment", solanaDeploymentFile(t, scratch, pin)}, nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"deposit without confirm":      {"deposit", "--keypair", "/k", "--sol", "1"},
		"deposit without keypair":      {"deposit", "--sol", "1", "--confirm"},
		"deposit bad amount":           {"deposit", "--keypair", "/k", "--sol", "1.0000000001", "--confirm"},
		"withdraw without confirm":     {"withdraw", "--to", pin.VaultState, "--all"},
		"withdraw without amount":      {"withdraw", "--to", pin.VaultState, "--confirm"},
		"withdraw all and amount":      {"withdraw", "--to", pin.VaultState, "--all", "--sol", "1", "--confirm"},
		"withdraw bad destination":     {"withdraw", "--to", "not-an-address", "--all", "--confirm"},
		"withdraw without destination": {"withdraw", "--all", "--confirm"},
	} {
		if err := runSolana(context.Background(), dir, args, nil, &bytes.Buffer{}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
