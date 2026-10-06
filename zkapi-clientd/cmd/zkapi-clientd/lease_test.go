package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestLeaseExportRequiresConfirmationAndPrintsNothingToStdout(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runLease(context.Background(), config.Config{}, []string{"export", "--usd", "5"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("err=%v", err)
	}
	if out.Len() != 0 || !strings.Contains(errOut.String(), "bearer") && !strings.Contains(errOut.String(), "spend") {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestLeaseExportRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"import"}, {"export"}, {"export", "--usd", "0", "--confirm"}, {"export", "--usd", "1000", "--confirm"}, {"export", "--usd", "1", "extra"}} {
		var out, errOut bytes.Buffer
		if err := runLease(context.Background(), config.Config{}, args, &out, &errOut); err == nil || out.Len() != 0 {
			t.Fatalf("args=%v err=%v stdout=%q", args, err, out.String())
		}
	}
}
