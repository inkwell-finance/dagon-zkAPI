package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validSolana() *Solana {
	s := &Solana{
		ServerURL: "http://127.0.0.1:8080", IndexerURL: "https://indexer.example.com", RPCURL: "https://rpc.example.com/solana", InferenceBase: "https://vcii.example.com/zk", Cluster: "mainnet-beta",
		ProgramID: "7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H", VaultState: "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE",
		GenesisHash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", ChainID: "11235813213455891", ProtocolBinding: "0x" + strings.Repeat("ab", 32),
		StateSigningKey:     CurvePoint{X: "0x" + strings.Repeat("11", 32), Y: "0x" + strings.Repeat("12", 32)},
		ClearanceSigningKey: CurvePoint{X: "0x" + strings.Repeat("21", 32), Y: "0x" + strings.Repeat("22", 32)},
		MinLeaseCredits:     12_000_000,
	}
	s.Normalize()
	return s
}

func TestSolanaProfileValidation(t *testing.T) {
	if err := validSolana().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Solana){
		"remote http server": func(s *Solana) { s.ServerURL = "http://example.com" },
		"credentials":        func(s *Solana) { s.IndexerURL = "https://user:pass@indexer.example.com" },
		"query":              func(s *Solana) { s.InferenceBase = "https://vcii.example.com/zk?x=1" },
		"short account":      func(s *Solana) { s.VaultState = "1111" },
		"bad alphabet":       func(s *Solana) { s.ProgramID = strings.Repeat("0", 44) },
		"zero binding":       func(s *Solana) { s.ProtocolBinding = "0x" + strings.Repeat("00", 32) },
		"chain id":           func(s *Solana) { s.ChainID = "0" },
		"signing key":        func(s *Solana) { s.StateSigningKey.X = "0xzz" },
		"no minimum":         func(s *Solana) { s.MinLeaseCredits = 0 },
		"price age":          func(s *Solana) { s.PythMaxAgeSeconds = 61 },
		"confidence":         func(s *Solana) { s.PythMaxConfidenceBps = 101 },
		"cluster label":      func(s *Solana) { s.Cluster = "Main Net" },
		"feed id":            func(s *Solana) { s.PythFeedID = "0xzz" },
		"no rpc":             func(s *Solana) { s.RPCURL = "" },
		"remote http rpc":    func(s *Solana) { s.RPCURL = "http://rpc.example.com" },
		"rpc credentials":    func(s *Solana) { s.RPCURL = "https://user:pass@rpc.example.com" },
		"rpc api key query":  func(s *Solana) { s.RPCURL = "https://rpc.example.com/?api-key=1" },
		"unpinned prover":    func(s *Solana) { s.Prover = "/usr/local/bin/zkapi-solana-wallet" },
		"short prover hash":  func(s *Solana) { s.Prover, s.ProverSHA256 = "/p", strings.Repeat("a", 63) },
		"uppercase hash":     func(s *Solana) { s.Prover, s.ProverSHA256 = "/p", strings.Repeat("A", 64) },
		"idle beyond a week": func(s *Solana) { idle := uint64(8 * 24 * 3600); s.SettleIdleSeconds = &idle },
	} {
		s := validSolana()
		mutate(s)
		if s.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSolanaNetworkRequiresItsPinAndOnlyIt(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	c.ZKAPI.Network = SolanaNetwork
	if Validate(c) == nil {
		t.Fatal("solana network accepted without a deployment pin")
	}
	c.ZKAPI.Solana = validSolana()
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	c.ZKAPI.Network = "mainnet"
	if Validate(c) == nil {
		t.Fatal("an Ethereum profile accepted a Solana pin")
	}
	c.ZKAPI.Network = SolanaNetwork
	dir := filepath.Join(t.TempDir(), "config")
	if err := Init(dir, c); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil || loaded.ZKAPI.Solana == nil || !reflect.DeepEqual(loaded.ZKAPI.Solana, c.ZKAPI.Solana) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestBase58Decode(t *testing.T) {
	if !Base58Account("11111111111111111111111111111111") {
		t.Fatal("the all-zero account (system program) must decode to 32 bytes")
	}
	if Base58Account("") || Base58Account("0OIl") || Base58Account("2") {
		t.Fatal("invalid base58 accepted")
	}
}

func TestSameFeltIgnoresZeroPadding(t *testing.T) {
	if !SameFelt("0xbe80d0", "0x00BE80D0") || SameFelt("0x1", "0x2") || SameFelt("zz", "0x1") {
		t.Fatal("felt comparison is not numeric")
	}
	s := validSolana()
	s.StateSigningKey.X = "0xbe80d0f61a801533a94a03b12683474f86ca012941db1c568c53dc877b16fd6" // 63 digits, as the helper prints it
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSolanaPinnedProverAndIdleSettlement(t *testing.T) {
	s := validSolana()
	s.Prover, s.ProverSHA256 = "/usr/local/bin/zkapi-solana-wallet", strings.Repeat("ab", 32)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.SettleIdle() != 15*time.Minute {
		t.Fatalf("default idle = %v", s.SettleIdle())
	}
	zero := uint64(0)
	s.SettleIdleSeconds = &zero
	if err := s.Validate(); err != nil || s.SettleIdle() != 0 {
		t.Fatalf("zero must disable idle settlement: %v %v", err, s.SettleIdle())
	}
	s.SettleIdleSeconds = nil
	s.Normalize()
	if s.SettleIdle() != 15*time.Minute || *s.SettleIdleSeconds != DefaultSettleIdleSeconds {
		t.Fatal("Normalize must pin the default")
	}
	s.SettleIdleSeconds = &zero
	s.Normalize()
	if *s.SettleIdleSeconds != 0 {
		t.Fatal("Normalize must not override an explicit zero")
	}
}

func TestBase58RoundTripsIncludingLeadingZeros(t *testing.T) {
	for _, data := range [][]byte{{0, 0, 1, 2, 3}, {255, 255}, make([]byte, 32), append(make([]byte, 5), 7)} {
		decoded, ok := Base58Decode(Base58Encode(data))
		if !ok || string(decoded) != string(data) {
			t.Fatalf("%x -> %q -> %x", data, Base58Encode(data), decoded)
		}
	}
	if Base58Encode(make([]byte, 32)) != strings.Repeat("1", 32) {
		t.Fatal("zero account must be 32 ones")
	}
	if Base58Encode(nil) != "" {
		t.Fatal("empty input")
	}
}
