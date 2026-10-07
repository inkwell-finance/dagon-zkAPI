package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

const solanaUsage = `usage: zkapi-clientd solana init --deployment FILE [--rpc-url URL] [--prover PATH --prover-sha256 HEX] [--proof-setup-dir DIR] [--settle-idle-seconds N] [--listen IP:PORT]
       zkapi-clientd solana deposit --keypair FILE --sol AMOUNT --confirm
       zkapi-clientd solana withdraw --to ADDRESS (--all | --sol AMOUNT) [--keypair FILE] --confirm
       zkapi-clientd solana verify
       zkapi-clientd solana import-wallet --file FILE|-
       zkapi-clientd solana status`

// runSolana handles the native-SOL profile commands. Leasing runs inside the
// daemon (zkapi-clientd serve); funding runs in this process, or through the
// daemon when one is running on the same configuration directory.
func runSolana(ctx context.Context, dir string, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(solanaUsage)
	}
	switch args[0] {
	case "init":
		return solanaInit(ctx, dir, args[1:], out)
	case "deposit":
		return solanaDeposit(ctx, dir, args[1:], out)
	case "withdraw":
		return solanaWithdraw(ctx, dir, args[1:], out)
	case "verify":
		return solanaVerify(ctx, dir, out)
	case "import-wallet":
		return solanaImport(dir, args[1:], in, out)
	case "status":
		return solanaStatus(dir, out)
	}
	return errors.New(solanaUsage)
}

func solanaInit(ctx context.Context, dir string, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("solana init", flag.ContinueOnError)
	deployment := flags.String("deployment", "", "JSON file with the pinned Solana deployment")
	prover := flags.String("prover", "", "zkapi-solana-wallet helper binary (overrides the deployment file)")
	proverHash := flags.String("prover-sha256", "", "SHA-256 of the helper binary, from the release notes (overrides the deployment file)")
	setup := flags.String("proof-setup-dir", "", "proving key directory holding request.pk and withdrawal.pk (overrides the deployment file)")
	rpcURL := flags.String("rpc-url", "", "Solana JSON-RPC used for on-chain verification and funding (overrides the deployment file)")
	idle := flags.Int64("settle-idle-seconds", -1, "settle an open lease after this many seconds without new usage; 0 disables (default 900)")
	listen := flags.String("listen", "", "numeric loopback API address and port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *deployment == "" {
		return errors.New(solanaUsage)
	}
	raw, err := os.ReadFile(*deployment)
	if err != nil {
		return errors.New("cannot read the deployment file")
	}
	var pin config.Solana
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pin); err != nil {
		return errors.New("invalid deployment file; check its field names and values")
	}
	if *prover != "" {
		pin.Prover = *prover
	}
	if *proverHash != "" {
		pin.ProverSHA256 = strings.ToLower(*proverHash)
	}
	if *setup != "" {
		pin.ProofSetupDir = *setup
	}
	if *rpcURL != "" {
		pin.RPCURL = *rpcURL
	}
	if *idle >= 0 {
		seconds := uint64(*idle)
		pin.SettleIdleSeconds = &seconds
	}
	pin.Normalize()
	// Persist paths independently of the directory from which serve is started.
	if pin.Prover != "" {
		pin.Prover, err = filepath.Abs(pin.Prover)
		if err != nil {
			return errors.New("cannot resolve the wallet helper path")
		}
	}
	if pin.ProofSetupDir != "" {
		pin.ProofSetupDir, err = filepath.Abs(pin.ProofSetupDir)
		if err != nil {
			return errors.New("cannot resolve the proof setup directory")
		}
	}
	if pin.Prover != "" && pin.ProverSHA256 == "" {
		observed, err := zkapi.HashFile(pin.Prover)
		if err != nil {
			return errors.New("cannot read the wallet helper binary")
		}
		return fmt.Errorf("pin the wallet helper: compare its SHA-256 with the release notes, then pass --prover-sha256 %s", observed)
	}
	// The chain ID and protocol binding are derived from the public identities by
	// the wallet helper. A file that states them must agree; one that omits them
	// is completed, so a typo can never pin a mismatched deployment.
	if pin.Prover != "" && pin.ProofSetupDir != "" {
		derived, err := zkapi.SolanaProverFor(pin).Derive(ctx, pin.ProgramID, pin.VaultState, pin.GenesisHash)
		if err != nil {
			return err
		}
		if (pin.ChainID != "" && pin.ChainID != derived.ChainID) || (pin.ProtocolBinding != "" && !config.SameFelt(pin.ProtocolBinding, derived.ProtocolBinding)) {
			return errors.New("the deployment file's chain_id or protocol_binding does not match its program, vault and genesis hash")
		}
		pin.ChainID, pin.ProtocolBinding = derived.ChainID, derived.ProtocolBinding
	}
	c, err := config.Default()
	if err != nil {
		return err
	}
	c.ZKAPI.Network, c.ZKAPI.Solana = config.SolanaNetwork, &pin
	if *listen != "" {
		c.Listen = *listen
	}
	if err := pin.Validate(); err != nil {
		return err
	}
	// Nothing is saved unless the chain agrees with every pin: a wrong program ID, vault, genesis
	// hash or signing key, a paused vault or a program that can still be upgraded is refused here.
	client, err := solanaHTTPClient(c)
	if err != nil {
		return err
	}
	vault, err := zkapi.VerifySolanaChain(ctx, client, pin)
	if err != nil {
		return err
	}
	if err := config.Init(dir, c); err != nil {
		return err
	}
	fmt.Fprintf(out, "Verified on chain: vault %s of immutable program %s (%d notes, per-request cap %d lamports).\n", pin.VaultState, pin.ProgramID, vault.NextNoteID, vault.RequestChargeCap)
	fmt.Fprintf(out, "Initialized the native-SOL profile for vault %s.\nFund it with zkapi-clientd solana deposit (or import a wallet with solana import-wallet), then run zkapi-clientd serve.\n", pin.VaultState)
	return nil
}

func loadSolanaProfile(dir string) (config.Config, *config.Solana, error) {
	c, err := config.Load(dir)
	if err != nil {
		return c, nil, configurationRequired(err)
	}
	if c.ZKAPI.Network != config.SolanaNetwork || c.ZKAPI.Solana == nil {
		return c, nil, errors.New("this profile is not a native-SOL profile; run zkapi-clientd solana init in an empty config directory")
	}
	return c, c.ZKAPI.Solana, nil
}

func solanaImport(dir string, args []string, in io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("solana import-wallet", flag.ContinueOnError)
	file := flags.String("file", "", "wallet export JSON, or - for standard input")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *file == "" {
		return errors.New(solanaUsage)
	}
	_, pin, err := loadSolanaProfile(dir)
	if err != nil {
		return err
	}
	var raw []byte
	if *file == "-" {
		raw, err = io.ReadAll(io.LimitReader(in, 1<<20))
	} else {
		raw, err = os.ReadFile(*file)
	}
	if err != nil {
		return errors.New("cannot read the wallet export")
	}
	if err := zkapi.ImportSolanaWallet(dir, *pin, raw); err != nil {
		return err
	}
	fmt.Fprintln(out, "Wallet imported. It holds the note secret: keep this configuration directory private and backed up.")
	return nil
}

func solanaStatus(dir string, out io.Writer) error {
	_, pin, err := loadSolanaProfile(dir)
	if err != nil {
		return err
	}
	wallet, err := zkapi.OpenSolanaWallet(dir, *pin, nil, nil)
	if err != nil {
		return err
	}
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(map[string]any{"network": "solana", "cluster": pin.Cluster, "vault_state": pin.VaultState, "wallet": wallet.Status()})
}

// solanaHTTPClient routes HTTPS through the configured relay and keeps
// loopback HTTP (a local test cluster) direct.
func solanaHTTPClient(c config.Config) (*http.Client, error) {
	secure, err := relay.NewClient(c.RelayURL)
	if err != nil {
		return nil, err
	}
	plain := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	return &http.Client{Transport: splitTransport{secure: secure.Transport, plain: plain}, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type splitTransport struct{ secure, plain http.RoundTripper }

func (t splitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme == "http" {
		return t.plain.RoundTrip(r)
	}
	return t.secure.RoundTrip(r)
}

// solanaBackend answers inference routes: a native-SOL profile issues leases for
// external services and has no OpenRouter chat bridge.
type solanaBackend struct{}

var errSolanaNoChat = &server.BackendError{Status: 501, Code: "not_supported", Message: "This native-SOL profile issues leases; use zkapi-clientd lease export."}

func (solanaBackend) Models(context.Context) (json.RawMessage, error) { return nil, errSolanaNoChat }
func (solanaBackend) Complete(context.Context, json.RawMessage) (*http.Response, error) {
	return nil, errSolanaNoChat
}

// serveSolana runs the loopback management API for a native-SOL wallet and
// settles its lease when due. It never starts the Ethereum companion.
func serveSolana(ctx context.Context, dir string, c config.Config, out io.Writer) error {
	logger := log.New(out, "zkapi-clientd ", log.LstdFlags)
	pin := c.ZKAPI.Solana
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("a zkAPI client daemon is already using this config directory")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	client, err := solanaHTTPClient(c)
	if err != nil {
		return err
	}
	wallet, err := zkapi.OpenSolanaWallet(dir, *pin, client, zkapi.SolanaProverFor(*pin))
	if err != nil {
		return err
	}
	// Refuse to serve a deployment the chain no longer agrees with (program upgraded or
	// replaced, vault paused or re-keyed, wrong cluster behind the RPC).
	if _, err := wallet.VerifyChain(ctx); err != nil {
		return err
	}
	logger.Printf("Verified on chain: vault %s of immutable program %s", pin.VaultState, pin.ProgramID)
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return errors.New("could not bind local API address; check for an existing service")
	}
	defer listener.Close()
	c.Listen = listener.Addr().String()
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	api, err := server.New(solanaBackend{}, c.APIKey, c.Concurrency)
	if err != nil {
		return err
	}
	api.RequireAPIKey = true
	api.ManagementToken = c.ManagementToken
	api.Admin = http.HandlerFunc(wallet.ServeAdminHTTP)
	api.Status = server.ServiceStatus{Backend: c.Backend, Network: config.SolanaNetwork, RequestBudgetPolicy: "lease"}
	httpServer := &http.Server{Handler: server.LogRequests(api, logger), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return life }}
	serverDone := make(chan error, 1)
	go func() { serverDone <- httpServer.Serve(listener) }()
	settled := make(chan struct{})
	go func() {
		defer close(settled)
		wallet.RunSettlement(life, func(format string, args ...any) { logger.Printf(format, args...) })
	}()
	logger.Printf("zkAPI client %s serving native-SOL leases for vault %s at http://%s (management only)", version, pin.VaultState, c.Listen)
	var result error
	select {
	case <-ctx.Done():
	case err := <-serverDone:
		if !errors.Is(err, http.ErrServerClosed) {
			result = errors.New("local API server stopped unexpectedly")
		}
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := httpServer.Shutdown(shutdown); err != nil {
		_ = httpServer.Close()
	}
	<-settled
	logger.Print("Local API service stopped")
	return result
}
