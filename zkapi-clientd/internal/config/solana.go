package config

import (
	"errors"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SolanaNetwork selects native-SOL leases against a pinned Solana vault. It has
// no Ethereum companion; wallet proofs come from the Solana wallet helper.
const SolanaNetwork = "solana"

// DefaultSettleIdleSeconds is how long an open lease may go without any new
// usage before it is settled early; 0 disables idle settlement.
const DefaultSettleIdleSeconds = 15 * 60

// Well-known Pyth identities for the sponsored SOL/USD feed. They are defaults
// for Solana.Normalize; every value is still pinned in the saved profile.
const (
	PythSolUsdFeedID         = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
	PythReceiverProgram      = "rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ"
	PythSolUsdShardZeroPrice = "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE"
)

// CurvePoint is a public signing key as hex field elements.
type CurvePoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// Solana is the operator-pinned native-SOL deployment. Nothing here is secret.
// The serverd attestation, billing quotes and leases must all match it, so a
// compromised or misconfigured server cannot move a wallet to another vault.
type Solana struct {
	ServerURL     string `json:"server_url"`     // serverd origin (HTTPS, or loopback HTTP)
	IndexerURL    string `json:"indexer_url"`    // finalized-account indexer (tree snapshots)
	RPCURL        string `json:"rpc_url"`        // Solana JSON-RPC for on-chain verification and funding (HTTPS, or loopback HTTP)
	InferenceBase string `json:"inference_base"` // provider base every lease must carry
	Cluster       string `json:"cluster"`        // label serverd quotes carry, e.g. mainnet-beta or localnet

	ProgramID       string `json:"program_id"`
	VaultState      string `json:"vault_state"`
	GenesisHash     string `json:"genesis_hash"`
	ChainID         string `json:"chain_id"`         // decimal proof chain ID derived from the genesis hash
	ProtocolBinding string `json:"protocol_binding"` // 0x felt derived from program, vault and genesis

	StateSigningKey     CurvePoint `json:"state_signing_key"`
	ClearanceSigningKey CurvePoint `json:"clearance_signing_key"`
	// MinLeaseCredits is the vault's per-request charge cap in lamports: the
	// smallest budget a lease proof may carry.
	MinLeaseCredits uint64 `json:"min_lease_lamports"`

	PythFeedID           string `json:"pyth_feed_id"`
	PythPriceAccount     string `json:"pyth_price_account"`
	PythReceiverProgram  string `json:"pyth_receiver_program"`
	PythMaxAgeSeconds    uint64 `json:"pyth_max_age_seconds"`
	PythMaxConfidenceBps uint64 `json:"pyth_max_confidence_bps"`

	Prover        string `json:"prover_binary,omitempty"`   // Solana wallet helper (zkapi-solana-wallet)
	ProverSHA256  string `json:"prover_sha256,omitempty"`   // pinned SHA-256 of the helper binary; a different file is never run
	ProofSetupDir string `json:"proof_setup_dir,omitempty"` // proving key directory (request.pk, withdrawal.pk)

	// SettleIdleSeconds settles an open lease early once its key has seen no new
	// usage for this long (default 900; 0 disables). Settlement also happens when the
	// lease's spending limit is used up, at its settle time, and on request.
	SettleIdleSeconds *uint64 `json:"settle_idle_seconds,omitempty"`
}

var (
	feltPattern    = regexp.MustCompile(`^0x[0-9a-fA-F]{1,64}$`)
	decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)
	clusterPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Normalize fills the documented Pyth defaults. It never invents deployment
// identity: the program, vault, genesis hash and keys must be supplied.
func (s *Solana) Normalize() {
	if s.SettleIdleSeconds == nil {
		idle := uint64(DefaultSettleIdleSeconds)
		s.SettleIdleSeconds = &idle
	}
	if s.PythFeedID == "" {
		s.PythFeedID = PythSolUsdFeedID
	}
	if s.PythReceiverProgram == "" {
		s.PythReceiverProgram = PythReceiverProgram
	}
	if s.PythPriceAccount == "" {
		s.PythPriceAccount = PythSolUsdShardZeroPrice
	}
	if s.PythMaxAgeSeconds == 0 {
		s.PythMaxAgeSeconds = 60
	}
	if s.PythMaxConfidenceBps == 0 {
		s.PythMaxConfidenceBps = 100
	}
}

// SettleIdle is the idle period after which an unused lease settles; zero
// disables idle settlement.
func (s *Solana) SettleIdle() time.Duration {
	if s.SettleIdleSeconds == nil {
		return DefaultSettleIdleSeconds * time.Second
	}
	return time.Duration(*s.SettleIdleSeconds) * time.Second
}

// ValidServiceURL accepts an HTTPS origin or a literal-loopback HTTP origin,
// without credentials, query or fragment.
func ValidServiceURL(raw string, allowPath bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if !allowPath && u.Path != "" && u.Path != "/" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		ip := net.ParseIP(u.Hostname())
		return ip != nil && ip.IsLoopback()
	}
	return false
}

func (s *Solana) Validate() error {
	if !ValidServiceURL(s.ServerURL, false) || !ValidServiceURL(s.IndexerURL, false) {
		return errors.New("solana server_url and indexer_url must be HTTPS or numeric-loopback HTTP origins")
	}
	if !ValidServiceURL(s.InferenceBase, true) {
		return errors.New("solana inference_base must be an HTTPS or numeric-loopback HTTP URL without credentials, query or fragment")
	}
	if !ValidServiceURL(s.RPCURL, true) {
		return errors.New("solana rpc_url must be an HTTPS or numeric-loopback HTTP URL without credentials, query or fragment")
	}
	if !clusterPattern.MatchString(s.Cluster) {
		return errors.New("solana cluster must be a short lowercase label")
	}
	for name, value := range map[string]string{
		"program_id": s.ProgramID, "vault_state": s.VaultState, "genesis_hash": s.GenesisHash,
		"pyth_price_account": s.PythPriceAccount, "pyth_receiver_program": s.PythReceiverProgram,
	} {
		if !Base58Account(value) {
			return errors.New("solana " + name + " must be a base58 32-byte account")
		}
	}
	if !decimalPattern.MatchString(s.ChainID) || s.ChainID == "0" || !feltPattern.MatchString(s.ProtocolBinding) || strings.Trim(s.ProtocolBinding[2:], "0") == "" {
		return errors.New("solana chain_id must be a decimal and protocol_binding a nonzero hex field element")
	}
	for _, point := range []CurvePoint{s.StateSigningKey, s.ClearanceSigningKey} {
		if !feltPattern.MatchString(point.X) || !feltPattern.MatchString(point.Y) {
			return errors.New("solana signing keys must be hex field elements")
		}
	}
	if !feltPattern.MatchString(s.PythFeedID) {
		return errors.New("solana pyth_feed_id must be a hex value")
	}
	if s.MinLeaseCredits == 0 || s.MinLeaseCredits > 1<<53 {
		return errors.New("solana min_lease_lamports must be positive and below 2^53")
	}
	if s.Prover != "" && !sha256Pattern.MatchString(s.ProverSHA256) {
		return errors.New("solana prover_sha256 must pin the helper binary: 64 lowercase hex digits (see the release notes)")
	}
	if s.SettleIdleSeconds != nil && *s.SettleIdleSeconds > 7*24*3600 {
		return errors.New("solana settle_idle_seconds must be at most one week (0 disables)")
	}
	if s.PythMaxAgeSeconds < 1 || s.PythMaxAgeSeconds > 60 || s.PythMaxConfidenceBps < 1 || s.PythMaxConfidenceBps > 100 {
		return errors.New("solana pyth safety bounds are out of range")
	}
	return nil
}

// SameFelt compares two hex field elements numerically: serializers differ on
// zero padding ("0x0abc" and "0xabc" are the same element).
func SameFelt(a, b string) bool {
	x, ok1 := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(a), "0x"), 16)
	y, ok2 := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(b), "0x"), 16)
	return ok1 && ok2 && x.Cmp(y) == 0
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58Account reports whether value is the canonical base58 form of 32 bytes.
func Base58Account(value string) bool {
	decoded, ok := Base58Decode(value)
	return ok && len(decoded) == 32
}

// Base58Encode is the Bitcoin-alphabet base58 form of data, with one '1' per leading zero byte.
func Base58Encode(data []byte) string {
	zeros := 0
	for zeros < len(data) && data[zeros] == 0 {
		zeros++
	}
	number := new(big.Int).SetBytes(data)
	base, mod := big.NewInt(58), new(big.Int)
	var digits []byte
	for number.Sign() > 0 {
		number.DivMod(number, base, mod)
		digits = append(digits, base58Alphabet[mod.Int64()])
	}
	out := make([]byte, 0, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out = append(out, digits[i])
	}
	return string(out)
}

// Base58Decode decodes Bitcoin-alphabet base58 including leading-zero bytes.
func Base58Decode(value string) ([]byte, bool) {
	if value == "" || len(value) > 90 {
		return nil, false
	}
	number := new(big.Int)
	base := big.NewInt(58)
	for _, character := range value {
		index := strings.IndexRune(base58Alphabet, character)
		if index < 0 {
			return nil, false
		}
		number.Mul(number, base)
		number.Add(number, big.NewInt(int64(index)))
	}
	zeros := 0
	for zeros < len(value) && value[zeros] == '1' {
		zeros++
	}
	body := number.Bytes()
	return append(make([]byte, zeros), body...), true
}
