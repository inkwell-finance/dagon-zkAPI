package zkapi

import (
	"context"
	"sync"
	"testing"
	"time"
)

// leaseUsage is a mutable usage reading that serverd's lease status reports for an active key.
type leaseUsage struct {
	mu    sync.Mutex
	usage *float64
	state string
	polls int
}

func (u *leaseUsage) set(value float64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.usage = &value
}

func (u *leaseUsage) unreadable() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.usage = nil
}

func (u *leaseUsage) handler() func(string) (int, any) {
	return func(string) (int, any) {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.polls++
		body := map[string]any{"status": u.state}
		if u.usage != nil {
			body["observed_usage_usd"] = *u.usage
		}
		return 200, body
	}
}

// earlyFixture is a wallet with one open 2 USD lease whose server reports live usage.
func earlyFixture(t *testing.T, idleSeconds *uint64) (*fixture, *leaseUsage) {
	t.Helper()
	f := newFixture(t, 1_000_000_000)
	if idleSeconds != nil {
		f.pin.SettleIdleSeconds = idleSeconds
		f.open()
	}
	f.server.leasePost = func(_ int, body []byte) (int, any) { return f.server.issued(body, nil) }
	if _, err := f.wallet.ExportLease(context.Background(), 2_000_000); err != nil {
		t.Fatal(err)
	}
	usage := &leaseUsage{state: "active"}
	usage.set(0)
	f.server.status = usage.handler()
	f.server.retire = func(int, string) (int, any) { return 200, map[string]any{"status": "finalized"} }
	f.server.settlement = settlementFor(f, "10000000")
	return f, usage
}

func (f *fixture) poll() error { return f.wallet.service(context.Background(), true, nil) }

func seconds(n uint64) *uint64 { return &n }

func TestAKeyThatUsedUpItsLimitSettlesAtOnce(t *testing.T) {
	f, usage := earlyFixture(t, seconds(0)) // idle settlement off: only exhaustion applies
	usage.set(1.2)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest {
		t.Fatalf("a partly used key must stay open: %v %+v", err, f.wallet.Status())
	}
	usage.set(2.0)
	if err := f.poll(); err != nil {
		t.Fatal(err)
	}
	if status := f.wallet.Status(); status.PendingRequest || status.Balance != "990000000" {
		t.Fatalf("an exhausted lease must be settled and installed: %+v", status)
	}
	if f.server.retires != 1 {
		t.Fatalf("retires=%d", f.server.retires)
	}
}

func TestAnIdleKeySettlesAfterThePeriodAndAUsedKeyDoesNot(t *testing.T) {
	f, usage := earlyFixture(t, seconds(600))
	started := f.server.now()
	// 9 minutes of silence: not yet.
	f.server.clock.Add(540)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest {
		t.Fatalf("settled before the idle period: %v", err)
	}
	// The key is used: the idle clock restarts from that observation.
	usage.set(0.4)
	if err := f.poll(); err != nil {
		t.Fatal(err)
	}
	if got := f.file().Lease.LastActivityAt; got != uint64(started+540) {
		t.Fatalf("activity time = %d, want %d", got, started+540)
	}
	// Another 9 minutes after that use: still open, although 18 minutes passed since issuance.
	f.server.clock.Add(540)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest {
		t.Fatalf("a key in active use was settled out from under its user: %v", err)
	}
	if f.server.retires != 0 {
		t.Fatal("retired while in use")
	}
	// Ten minutes without a new reading of usage: settled.
	f.server.clock.Add(61)
	if err := f.poll(); err != nil {
		t.Fatal(err)
	}
	if status := f.wallet.Status(); status.PendingRequest || status.Balance != "990000000" {
		t.Fatalf("an idle key must settle: %+v", status)
	}
}

func TestAnUnusedKeySettlesAfterTheIdlePeriodFromIssuance(t *testing.T) {
	f, _ := earlyFixture(t, seconds(300))
	f.server.clock.Add(299)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest {
		t.Fatalf("settled early: %v", err)
	}
	f.server.clock.Add(1)
	if err := f.poll(); err != nil || f.wallet.Status().PendingRequest {
		t.Fatalf("an unused key must settle once the idle period passed: %v %+v", err, f.wallet.Status())
	}
}

func TestIdleSettlementCanBeDisabledAndTheDefaultIsFifteenMinutes(t *testing.T) {
	f, _ := earlyFixture(t, seconds(0))
	f.server.clock.Add(3000)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest {
		t.Fatalf("0 disables idle settlement: %v", err)
	}
	g, _ := earlyFixture(t, nil) // the default
	g.server.clock.Add(14*60 + 59)
	if err := g.poll(); err != nil || !g.wallet.Status().PendingRequest {
		t.Fatalf("settled before the 15 minute default: %v", err)
	}
	g.server.clock.Add(1)
	if err := g.poll(); err != nil || g.wallet.Status().PendingRequest {
		t.Fatalf("not settled at the 15 minute default: %v", err)
	}
}

func TestNothingIsSettledEarlyWhenUsageCannotBeRead(t *testing.T) {
	f, usage := earlyFixture(t, seconds(60))
	usage.unreadable()
	f.server.clock.Add(1800)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest || f.server.retires != 0 {
		t.Fatalf("an unreadable usage must never settle a lease: %v retires=%d", err, f.server.retires)
	}
	// Garbage readings are ignored too.
	usage.set(-1)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest {
		t.Fatalf("a negative reading settled the lease: %v", err)
	}
}

func TestAServerErrorWhilePollingKeepsTheLeaseOpen(t *testing.T) {
	f, _ := earlyFixture(t, seconds(60))
	f.server.status = func(string) (int, any) { return 503, nil }
	f.server.clock.Add(1800)
	if err := f.poll(); err == nil || !f.wallet.Status().PendingRequest || f.server.retires != 0 {
		t.Fatalf("a failing status read must not settle (err=%v)", err)
	}
}

func TestIdleClockSurvivesARestart(t *testing.T) {
	f, usage := earlyFixture(t, seconds(600))
	f.server.clock.Add(400)
	usage.set(0.3)
	if err := f.poll(); err != nil {
		t.Fatal(err)
	}
	f.open() // a restarted daemon reads the activity time from the wallet file
	f.server.clock.Add(400)
	if err := f.poll(); err != nil || !f.wallet.Status().PendingRequest {
		t.Fatalf("the restart forgot the last activity and settled early or failed: %v", err)
	}
	f.server.clock.Add(201)
	if err := f.poll(); err != nil || f.wallet.Status().PendingRequest {
		t.Fatalf("an idle key must settle after a restart: %v", err)
	}
}

func TestAnAlreadyRetiredLeaseIsFinishedWhenPollingSeesIt(t *testing.T) {
	f, usage := earlyFixture(t, seconds(900))
	usage.mu.Lock()
	usage.state = "disabled"
	usage.mu.Unlock()
	if err := f.poll(); err != nil || f.wallet.Status().PendingRequest {
		t.Fatalf("a lease the server already retired must be installed: %v %+v", err, f.wallet.Status())
	}
}

func TestStatusShowsWhenAnIdleLeaseWillSettle(t *testing.T) {
	f, usage := earlyFixture(t, seconds(600))
	f.server.clock.Add(100)
	usage.set(0.25)
	if err := f.poll(); err != nil {
		t.Fatal(err)
	}
	status := f.wallet.Status()
	if status.LeaseUsageUSD != 0.25 || status.IdleSettleAt != uint64(f.server.now())+600 {
		t.Fatalf("status: %+v (now %d)", status, f.server.now())
	}
	off, _ := earlyFixture(t, seconds(0))
	if off.wallet.Status().IdleSettleAt != 0 {
		t.Fatal("no idle deadline when idle settlement is off")
	}
}

func TestRunSettlementPollsUsageAndSettlesAnIdleLeaseOnItsOwn(t *testing.T) {
	f, usage := earlyFixture(t, seconds(4)) // polls about every second
	usage.set(0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.wallet.RunSettlement(ctx, nil)
	}()
	defer func() {
		cancel()
		<-done
	}()
	time.Sleep(300 * time.Millisecond)
	if !f.wallet.Status().PendingRequest {
		t.Fatal("settled before any idle time passed")
	}
	f.server.clock.Add(5) // five idle seconds on the wallet's clock
	deadline := time.Now().Add(15 * time.Second)
	for f.wallet.Status().PendingRequest && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if status := f.wallet.Status(); status.PendingRequest || status.Balance != "990000000" {
		t.Fatalf("the background loop did not settle the idle lease: %+v", status)
	}
	usage.mu.Lock()
	polls := usage.polls
	usage.mu.Unlock()
	if polls == 0 {
		t.Fatal("the loop never read the lease's usage")
	}
}

func TestRunSettlementKeepsAnActiveLeaseOpenWhileItsUsageGrows(t *testing.T) {
	f, usage := earlyFixture(t, seconds(4))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.wallet.RunSettlement(ctx, nil)
	}()
	defer func() {
		cancel()
		<-done
	}()
	grown := 0.0
	for i := 0; i < 6; i++ {
		grown += 0.1
		usage.set(grown)
		f.server.clock.Add(3) // less than the idle period between two uses
		time.Sleep(1300 * time.Millisecond)
	}
	if !f.wallet.Status().PendingRequest {
		t.Fatal("a key with growing usage was settled")
	}
}

func TestUnknownStatusCannotAuthorizeEarlyRetirement(t *testing.T) {
	f, usage := earlyFixture(t, seconds(60))
	usage.state = "future_state"
	f.server.clock.Add(100)
	if err := f.poll(); err == nil || f.server.retires != 0 || !f.wallet.Status().PendingRequest {
		t.Fatalf("unknown status retired a key: err=%v retires=%d", err, f.server.retires)
	}
}

func TestRegressingAndOverflowUsageCannotAuthorizeIdleRetirement(t *testing.T) {
	for _, reading := range []float64{0.1, 1e300} {
		f, usage := earlyFixture(t, seconds(60))
		usage.set(0.5)
		if err := f.poll(); err != nil {
			t.Fatal(err)
		}
		f.server.clock.Add(100)
		usage.set(reading)
		if err := f.poll(); err != nil || f.server.retires != 0 || !f.wallet.Status().PendingRequest {
			t.Fatalf("invalid reading %g retired a key: err=%v retires=%d", reading, err, f.server.retires)
		}
	}
}

func TestLegacyLeaseStartsAConservativeIdleClockAfterReopening(t *testing.T) {
	f, _ := earlyFixture(t, seconds(60))
	if err := f.wallet.update(func(file *solanaWalletFile) { file.Lease.LastActivityAt = 0 }); err != nil {
		t.Fatal(err)
	}
	f.open()
	f.server.clock.Add(100)
	if err := f.poll(); err != nil || f.server.retires != 0 || !f.wallet.Status().PendingRequest {
		t.Fatalf("legacy lease retired on first poll: %v", err)
	}
	if f.file().Lease.LastActivityAt != uint64(f.server.now()) {
		t.Fatal("missing durable idle baseline")
	}
	f.server.clock.Add(60)
	if err := f.poll(); err != nil || f.wallet.Status().PendingRequest {
		t.Fatalf("legacy lease did not retire after full idle period: %v", err)
	}
}
