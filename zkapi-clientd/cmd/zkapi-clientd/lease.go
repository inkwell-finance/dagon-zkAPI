package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

const leaseExportWarning = `Exporting a lease key hands a spendable bearer token to another program.
Anyone holding it can spend up to the cap until it expires, and it cannot be recovered if lost.
Reusing one key across requests links those requests to each other (not to your wallet).
Only one lease is open per wallet: the next lease waits until this key expires and settles.
The key is printed once to standard output and is never stored or logged by zkapi-clientd.`

// runLease handles "zkapi-clientd lease export". The running daemon opens the
// lease; this command only asks it over the authenticated loopback interface.
func runLease(ctx context.Context, c config.Config, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] != "export" {
		return errors.New("usage: zkapi-clientd lease export --usd AMOUNT --confirm")
	}
	flags := flag.NewFlagSet("lease export", flag.ContinueOnError)
	usdText := flags.String("usd", "", "spending cap for the key in USD, up to 6 decimal places")
	confirm := flags.Bool("confirm", false, "acknowledge that the key is a spendable bearer token shown once")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*usdText) == "" {
		return errors.New("usage: zkapi-clientd lease export --usd AMOUNT --confirm")
	}
	limit, err := parseFundingAmountForAsset(*usdText, 6, "USD")
	if err != nil {
		return err
	}
	if limit > zkapi.MaxExportLimitMicroUSD {
		return fmt.Errorf("cap exceeds the client maximum of %s USD", fundingUnits(fmt.Sprint(zkapi.MaxExportLimitMicroUSD), 6))
	}
	if !*confirm {
		fmt.Fprintln(errOut, leaseExportWarning)
		return errors.New("rerun with --confirm to open the lease and print the key")
	}
	c, err = activeFundingConfig(ctx, c)
	if err != nil {
		return err
	}
	var lease zkapi.ExportedLease
	if err := requestManagementJSON(ctx, c, http.MethodPost, "/admin/lease/export", map[string]any{"request_limit_micro_usd": limit, "confirm": true}, &lease); err != nil {
		return err
	}
	if lease.APIKey == "" || strings.ContainsAny(lease.APIKey, "\r\n \t") || lease.LimitMicroUSD != limit {
		return errors.New("invalid lease export response")
	}
	fmt.Fprintf(errOut, "Lease cap %s USD, expires %s.\nProvider base: %s\nVerification: %s\n", fundingUnits(fmt.Sprint(limit), 6), time.Unix(int64(lease.ExpiresAt), 0).UTC().Format(time.RFC3339), lease.BaseURL, lease.VerificationStatus)
	fmt.Fprintln(out, lease.APIKey)
	return nil
}
