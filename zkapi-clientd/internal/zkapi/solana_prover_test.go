package zkapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

// helperScript writes a stand-in helper. HELLO is its handshake result; every
// command line it receives is appended to <dir>/seen, and it leaves <dir>/ran.
func helperScript(t *testing.T, hello string, extra string) (binary, dir string) {
	t.Helper()
	dir = t.TempDir()
	binary = filepath.Join(dir, "zkapi-solana-wallet")
	body := `#!/bin/sh
touch "` + dir + `/ran"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "` + dir + `/seen"
  id=$(printf '%s' "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
  case "$line" in
    *'"command":"handshake"'*) printf '{"id":%s,"ok":true,"result":` + hello + `}\n' "$id" ;;
    *'"command":"connect"'*) printf '{"id":%s,"ok":true,"result":{"connected":true}}\n' "$id" ;;
` + extra + `
    *) printf '{"id":%s,"ok":false,"error":"secret detail 0xdeadbeef"}\n' "$id" ;;
  esac
done
`
	if err := os.WriteFile(binary, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return binary, dir
}

const goodHello = `{"name":"zkapi-solana-wallet","version":"0.1.0","protocol":1,"dev":false}`

func digestOf(t *testing.T, path string) string {
	t.Helper()
	sum, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func TestHelperWithAnotherDigestIsNeverRun(t *testing.T) {
	binary, dir := helperScript(t, goodHello, "")
	prover := ExecSolanaProver{Binary: binary, SetupDir: dir, SHA256: strings.Repeat("0", 64)}
	if _, err := prover.Derive(context.Background(), "p", "v", "g"); errorCode(err) != "solana_prover_hash_mismatch" {
		t.Fatalf("a binary that is not the pinned one must be refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
		t.Fatal("the unpinned binary was executed")
	}
	// Every funding entry point goes through the same check.
	if _, err := prover.NoteStatus(context.Background(), 1); errorCode(err) != "solana_prover_hash_mismatch" {
		t.Fatalf("note status: %v", err)
	}
	if _, err := prover.SignOperation(context.Background(), "k", []byte(`{}`)); errorCode(err) != "solana_prover_hash_mismatch" {
		t.Fatalf("sign: %v", err)
	}
	// The binary is swapped after pinning.
	prover.SHA256 = digestOf(t, binary)
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ntouch "+dir+"/swapped\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := prover.Derive(context.Background(), "p", "v", "g"); errorCode(err) != "solana_prover_hash_mismatch" {
		t.Fatalf("a binary swapped after pinning must be refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "swapped")); err == nil {
		t.Fatal("the swapped binary ran")
	}
}

func TestHelperHandshakeMustMatchTheProtocolAndName(t *testing.T) {
	for name, test := range map[string]struct {
		hello string
		code  string
	}{
		"newer protocol":  {`{"name":"zkapi-solana-wallet","version":"9.0.0","protocol":2,"dev":false}`, "solana_prover_protocol_mismatch"},
		"older protocol":  {`{"name":"zkapi-solana-wallet","version":"0.0.1","protocol":0,"dev":false}`, "solana_prover_protocol_mismatch"},
		"another program": {`{"name":"something-else","version":"0.1.0","protocol":1,"dev":false}`, "solana_prover_handshake_failed"},
		"no answer":       {`"nope"`, "solana_prover_handshake_failed"},
		"dev build":       {`{"name":"zkapi-solana-wallet","version":"0.1.0","protocol":1,"dev":true}`, "solana_prover_dev_build"},
	} {
		binary, dir := helperScript(t, test.hello, "")
		prover := ExecSolanaProver{Binary: binary, SetupDir: dir, SHA256: digestOf(t, binary)}
		if _, err := prover.NoteStatus(context.Background(), 1); errorCode(err) != test.code {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestADevBuildIsAcceptedOnlyForALocalTestCluster(t *testing.T) {
	devHello := `{"name":"zkapi-solana-wallet","version":"0.1.0","protocol":1,"dev":true}`
	binary, dir := helperScript(t, devHello, `    *'"command":"note_status"'*) printf '{"id":%s,"ok":true,"result":{"exists":false}}\n' "$id" ;;`)
	pin := testPin("http://127.0.0.1:1")
	pin.Prover, pin.ProofSetupDir, pin.ProverSHA256 = binary, dir, digestOf(t, binary)
	pin.Cluster = "localnet"
	if _, err := SolanaProverFor(pin).NoteStatus(context.Background(), 1); err != nil {
		t.Fatalf("localnet profile: %v", err)
	}
	for _, cluster := range []string{"mainnet-beta", "devnet", "testnet"} {
		pin.Cluster = cluster
		if _, err := SolanaProverFor(pin).NoteStatus(context.Background(), 1); errorCode(err) != "solana_prover_dev_build" {
			t.Fatalf("%s must refuse a dev build: %v", cluster, err)
		}
	}
}

func TestFundingCommandsConnectToThePinnedChainAfterTheHandshake(t *testing.T) {
	extra := `    *'"command":"deposit_prepare"'*) printf '{"id":%s,"ok":true,"result":{"note_id":4,"operation":{"operation_id":"ab","transactions":[]}}}\n' "$id" ;;
    *'"command":"nullifier_status"'*) printf '{"id":%s,"ok":true,"result":{"used":true}}\n' "$id" ;;
    *'"command":"signed_status"'*) printf '{"id":%s,"ok":true,"result":{"transactions":[{"signature":"s","progress":"finalized","failed":false}],"expired":false}}\n' "$id" ;;
    *'"command":"note_status"'*) printf '{"id":%s,"ok":true,"result":{"exists":true,"commitment":"0x01","amount":7,"expiry":9,"active":true}}\n' "$id" ;;`
	binary, dir := helperScript(t, goodHello, extra)
	pin := testPin("http://127.0.0.1:1")
	pin.RPCURL = "https://rpc.example.com/solana"
	pin.Prover, pin.ProofSetupDir, pin.ProverSHA256 = binary, dir, digestOf(t, binary)
	prover := SolanaProverFor(pin)
	noteID, operation, err := prover.PrepareDeposit(context.Background(), "payer", "0xc", 5)
	if err != nil || noteID != 4 || !strings.Contains(string(operation), `"operation_id":"ab"`) {
		t.Fatalf("prepare: %d %s %v", noteID, operation, err)
	}
	if used, err := prover.NullifierUsed(context.Background(), "0x1"); err != nil || !used {
		t.Fatalf("nullifier: %v %v", used, err)
	}
	status, err := prover.SignedStatus(context.Background(), []byte(`{}`))
	if err != nil || !status.allFinalized() || status.anyFailed() {
		t.Fatalf("status: %+v %v", status, err)
	}
	note, err := prover.NoteStatus(context.Background(), 4)
	if err != nil || !note.Exists || note.Amount != 7 || note.Expiry != 9 || !config.SameFelt(note.Commitment, "0x01") {
		t.Fatalf("note: %+v %v", note, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "seen"))
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if !strings.Contains(lines[0], `"command":"handshake"`) || !strings.Contains(lines[1], `"command":"connect"`) {
		t.Fatalf("a session must handshake first, then connect: %v", lines[:2])
	}
	connect := lines[1]
	for _, want := range []string{`"rpc_url":"https://rpc.example.com/solana"`, `"program_id":"` + pin.ProgramID + `"`, `"vault_state":"` + pin.VaultState + `"`,
		`"genesis_hash":"` + pin.GenesisHash + `"`, `"network":"localnet"`} {
		if !strings.Contains(connect, want) {
			t.Errorf("connect %q lacks %s", connect, want)
		}
	}
	// Secret-free commands never need a chain.
	_ = os.Remove(filepath.Join(dir, "seen"))
	if _, err := prover.DepositParams(context.Background()); err == nil {
		t.Fatal("the stand-in helper has no deposit_params; expected a refusal")
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "seen"))
	if strings.Contains(string(raw), `"command":"connect"`) {
		t.Fatalf("deposit_params must not connect: %s", raw)
	}
}

func TestHelperRefusalsExposeOnlyKnownCodes(t *testing.T) {
	extra := `    *'"command":"deposit_prepare"'*) printf '{"id":%s,"ok":false,"error":"leaked 0xsecret","code":"stale_root"}\n' "$id" ;;
    *'"command":"submit_signed"'*) printf '{"id":%s,"ok":false,"error":"leaked 0xsecret","code":"blockhash_expired"}\n' "$id" ;;
    *'"command":"nullifier_status"'*) printf '{"id":%s,"ok":false,"error":"leaked 0xsecret","code":"made_up_code"}\n' "$id" ;;`
	binary, dir := helperScript(t, goodHello, extra)
	pin := testPin("http://127.0.0.1:1")
	pin.Prover, pin.ProofSetupDir, pin.ProverSHA256 = binary, dir, digestOf(t, binary)
	prover := SolanaProverFor(pin)
	_, _, err := prover.PrepareDeposit(context.Background(), "p", "0x1", 1)
	if helperCode(err) != helperStaleRoot || strings.Contains(err.Error(), "secret") {
		t.Fatalf("stale root: %v", err)
	}
	_, err = prover.SubmitSigned(context.Background(), []byte(`{}`), true)
	if helperCode(err) != helperBlockhash {
		t.Fatalf("blockhash: %v", err)
	}
	_, err = prover.NullifierUsed(context.Background(), "0x1")
	if err == nil || helperCode(err) != "" || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "made_up") {
		t.Fatalf("an unknown code must collapse to a generic refusal: %v", err)
	}
}

func TestHelperPinExecutesTheHashedFileInsteadOfSearchingPATH(t *testing.T) {
	pinned, dir := helperScript(t, goodHello, "")
	_, otherDir := helperScript(t, goodHello, "")
	t.Chdir(dir)
	t.Setenv("PATH", otherDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	prover := ExecSolanaProver{Binary: filepath.Base(pinned), SetupDir: dir, SHA256: digestOf(t, pinned)}
	session, cancel, err := prover.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session.close()
	cancel()
	if _, err := os.Stat(filepath.Join(dir, "ran")); err != nil {
		t.Fatal("the hashed helper was not run", err)
	}
	if _, err := os.Stat(filepath.Join(otherDir, "ran")); err == nil {
		t.Fatal("an unpinned helper from PATH was executed")
	}
}
