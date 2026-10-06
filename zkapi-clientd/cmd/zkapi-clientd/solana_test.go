package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

const solanaTestBinding = "0x" + "bb00000000000000000000000000000000000000000000000000000000000002"

func solanaDeploymentFile(t *testing.T, dir string) string {
	t.Helper()
	deployment := map[string]any{
		"server_url": "http://127.0.0.1:9", "indexer_url": "http://127.0.0.1:10", "inference_base": "http://127.0.0.1:11/zk", "cluster": "localnet",
		"program_id": "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H", "vault_state": "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE",
		"genesis_hash": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", "chain_id": "11235813213455891", "protocol_binding": solanaTestBinding,
		"state_signing_key":     map[string]string{"x": "0x" + strings.Repeat("11", 32), "y": "0x" + strings.Repeat("12", 32)},
		"clearance_signing_key": map[string]string{"x": "0x" + strings.Repeat("21", 32), "y": "0x" + strings.Repeat("22", 32)},
		"min_lease_lamports":    12000000,
	}
	raw, _ := json.Marshal(deployment)
	path := filepath.Join(dir, "deployment.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSolanaInitImportAndStatus(t *testing.T) {
	scratch := t.TempDir()
	dir := filepath.Join(scratch, "cfg")
	var out bytes.Buffer
	if err := runSolana(context.Background(), dir, []string{"init", "--deployment", solanaDeploymentFile(t, scratch)}, nil, &out); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(dir)
	if err != nil || c.ZKAPI.Network != config.SolanaNetwork || c.ZKAPI.Solana == nil || c.ZKAPI.Solana.PythMaxAgeSeconds != 60 || c.ZKAPI.Solana.PythPriceAccount == "" {
		t.Fatalf("saved profile: %+v err=%v", c.ZKAPI, err)
	}
	if err := runSolana(context.Background(), dir, []string{"init", "--deployment", solanaDeploymentFile(t, scratch)}, nil, &out); err == nil {
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
	path := solanaDeploymentFile(t, scratch)
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
