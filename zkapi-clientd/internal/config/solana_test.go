package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func validSolana() *Solana {
	s := &Solana{
		ServerURL: "http://127.0.0.1:8080", IndexerURL: "https://indexer.example.com", InferenceBase: "https://vcii.example.com/zk", Cluster: "mainnet-beta",
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
	if err != nil || loaded.ZKAPI.Solana == nil || *loaded.ZKAPI.Solana != *c.ZKAPI.Solana {
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
