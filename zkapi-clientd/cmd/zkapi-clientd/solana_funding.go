package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

const depositWarning = `A deposit moves native SOL from your keypair into the Solana vault and registers a private note.
The note secret is saved only in this configuration directory's wallet file: keep the directory private and backed up.
The deposit is journaled before it touches the chain; if it is interrupted, run the same command again or start zkapi-clientd serve and it resumes from the chain.`

const withdrawWarning = `A withdrawal closes your note and pays its whole private balance to the address.
It cannot be undone, and the note cannot be used for leases once clearance is requested.
It is journaled before it touches the chain; if it is interrupted, run the same command again or start zkapi-clientd serve and it resumes from the chain.`

// fundingRun runs one funding operation. With no daemon on the configuration
// directory the operation runs here, holding the daemon lock so none can start
// meanwhile. With a daemon running, the daemon (which owns the wallet file in
// memory) runs it: this process only asks over the authenticated loopback API.
func fundingRun(ctx context.Context, dir string, c config.Config, pin *config.Solana, errOut io.Writer, create bool,
	local func(*zkapi.SolanaWallet) (zkapi.FundingResult, error), path string, body map[string]any) (zkapi.FundingResult, error) {
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return zkapi.FundingResult{}, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fmt.Fprintln(errOut, "A zkapi-clientd daemon is running: asking it to do this.")
		active, err := activeFundingConfig(ctx, c)
		if err != nil {
			return zkapi.FundingResult{}, err
		}
		var result zkapi.FundingResult
		err = requestManagementJSON(ctx, active, http.MethodPost, path, body, &result)
		return result, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	client, err := solanaHTTPClient(c)
	if err != nil {
		return zkapi.FundingResult{}, err
	}
	prover := zkapi.SolanaProverFor(*pin)
	wallet, err := zkapi.OpenSolanaWallet(dir, *pin, client, prover)
	if errors.Is(err, zkapi.ErrNoSolanaWallet) && create {
		if err := zkapi.InitSolanaWallet(ctx, dir, *pin, prover); err != nil {
			return zkapi.FundingResult{}, err
		}
		wallet, err = zkapi.OpenSolanaWallet(dir, *pin, client, prover)
	}
	if err != nil {
		return zkapi.FundingResult{}, err
	}
	return local(wallet)
}

func printFunding(out io.Writer, result zkapi.FundingResult) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func solanaDeposit(ctx context.Context, dir string, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("solana deposit", flag.ContinueOnError)
	keypair := flags.String("keypair", "", "Solana keypair file (JSON byte array) that pays the deposit and the fees")
	sol := flags.String("sol", "", "amount to deposit in SOL, up to 9 decimal places")
	confirm := flags.Bool("confirm", false, "acknowledge the deposit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *keypair == "" {
		return errors.New("usage: zkapi-clientd solana deposit --keypair FILE --sol AMOUNT --confirm")
	}
	var lamports uint64
	if *sol != "" {
		var err error
		if lamports, err = parseFundingAmountForAsset(*sol, 9, "SOL"); err != nil {
			return err
		}
	}
	c, pin, err := loadSolanaProfile(dir)
	if err != nil {
		return err
	}
	if !*confirm {
		fmt.Fprintln(os.Stderr, depositWarning)
		return errors.New("rerun with --confirm to deposit")
	}
	absolute, err := filepath.Abs(*keypair)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Depositing: this waits for Solana finality (typically under a minute; a first run also proves the vault transition).")
	result, err := fundingRun(ctx, dir, c, pin, os.Stderr, true,
		func(w *zkapi.SolanaWallet) (zkapi.FundingResult, error) {
			return w.Deposit(ctx, zkapi.DepositRequest{KeypairPath: absolute, Lamports: lamports})
		},
		"/admin/solana/deposit", map[string]any{"keypair": absolute, "lamports": lamports, "confirm": true})
	if err != nil {
		return err
	}
	return printFunding(out, result)
}

func solanaWithdraw(ctx context.Context, dir string, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("solana withdraw", flag.ContinueOnError)
	to := flags.String("to", "", "Solana address that receives the funds")
	all := flags.Bool("all", false, "withdraw the whole private balance")
	sol := flags.String("sol", "", "amount in SOL; must equal the whole private balance (the vault closes a note as a whole)")
	keypair := flags.String("keypair", "", "Solana keypair file that pays the transaction fees (default: the one used for the deposit)")
	confirm := flags.Bool("confirm", false, "acknowledge the withdrawal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	usage := errors.New("usage: zkapi-clientd solana withdraw --to ADDRESS (--all | --sol AMOUNT) [--keypair FILE] --confirm")
	if flags.NArg() != 0 || *to == "" || *all == (*sol != "") {
		return usage
	}
	var lamports uint64
	if *sol != "" {
		var err error
		if lamports, err = parseFundingAmountForAsset(*sol, 9, "SOL"); err != nil {
			return err
		}
	}
	*to = strings.TrimSpace(*to)
	if !config.Base58Account(*to) {
		return errors.New("--to must be a base58 Solana address")
	}
	c, pin, err := loadSolanaProfile(dir)
	if err != nil {
		return err
	}
	if !*confirm {
		fmt.Fprintln(os.Stderr, withdrawWarning)
		return errors.New("rerun with --confirm to withdraw")
	}
	absolute := ""
	if *keypair != "" {
		if absolute, err = filepath.Abs(*keypair); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "Withdrawing: this proves the close and waits for Solana finality (about a minute).")
	result, err := fundingRun(ctx, dir, c, pin, os.Stderr, false,
		func(w *zkapi.SolanaWallet) (zkapi.FundingResult, error) {
			return w.Withdraw(ctx, zkapi.WithdrawRequest{Destination: *to, KeypairPath: absolute, All: *all, Lamports: lamports})
		},
		"/admin/solana/withdraw", map[string]any{"to": *to, "keypair": absolute, "all": *all, "lamports": lamports, "confirm": true})
	if err != nil {
		return err
	}
	return printFunding(out, result)
}

// solanaVerify reads the chain through the pinned RPC and checks every pin.
func solanaVerify(ctx context.Context, dir string, out io.Writer) error {
	c, pin, err := loadSolanaProfile(dir)
	if err != nil {
		return err
	}
	client, err := solanaHTTPClient(c)
	if err != nil {
		return err
	}
	vault, err := zkapi.VerifySolanaChain(ctx, client, *pin)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{"verified": true, "program_id": pin.ProgramID, "program_upgradeable": false, "vault_state": pin.VaultState,
		"genesis_hash": pin.GenesisHash, "notes": vault.NextNoteID, "request_charge_cap_lamports": vault.RequestChargeCap})
}
