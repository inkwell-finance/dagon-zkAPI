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
	"syscall"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

const solanaUsage = `usage: zkapi-clientd solana init --deployment FILE [--prover PATH] [--proof-setup-dir DIR] [--listen IP:PORT]
       zkapi-clientd solana import-wallet --file FILE|-
       zkapi-clientd solana status`

// runSolana handles the native-SOL profile commands. They work on saved files
// only; leasing runs inside the daemon (zkapi-clientd serve).
func runSolana(ctx context.Context, dir string, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(solanaUsage)
	}
	switch args[0] {
	case "init":
		return solanaInit(ctx, dir, args[1:], out)
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
	prover := flags.String("prover", "", "Solana wallet helper binary (overrides the deployment file)")
	setup := flags.String("proof-setup-dir", "", "request proving key directory (overrides the deployment file)")
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
	if *setup != "" {
		pin.ProofSetupDir = *setup
	}
	pin.Normalize()
	// The chain ID and protocol binding are derived from the public identities by
	// the wallet helper. A file that states them must agree; one that omits them
	// is completed, so a typo can never pin a mismatched deployment.
	if pin.Prover != "" && pin.ProofSetupDir != "" {
		derived, err := zkapi.ExecSolanaProver{Binary: pin.Prover, SetupDir: pin.ProofSetupDir}.Derive(ctx, pin.ProgramID, pin.VaultState, pin.GenesisHash)
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
	if err := config.Init(dir, c); err != nil {
		return err
	}
	fmt.Fprintf(out, "Initialized the native-SOL profile for vault %s.\nImport a funded wallet with zkapi-clientd solana import-wallet, then run zkapi-clientd serve.\n", pin.VaultState)
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
	wallet, err := zkapi.OpenSolanaWallet(dir, *pin, client, zkapi.ExecSolanaProver{Binary: pin.Prover, SetupDir: pin.ProofSetupDir})
	if err != nil {
		return err
	}
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
