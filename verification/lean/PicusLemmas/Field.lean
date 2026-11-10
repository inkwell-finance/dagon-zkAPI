import Mathlib.NumberTheory.LucasPrimality
import Mathlib.NumberTheory.LegendreSymbol.Basic
import Mathlib.Tactic.NormNum.Prime

/-!
# The BN254 scalar field, with a machine-checked primality certificate

`p` is the BN254 scalar field modulus (the base field of Baby Jubjub / `ark-ed-on-bn254`).
Primality is proved with a Pratt (Lucas) certificate: every modular power is computed by the
kernel (`decide +kernel`) with the binary-exponentiation function `powModAux`, whose
correctness (`powModAux_eq`) is proved below. Small primes are discharged by `norm_num`.
-/

namespace Picus

/-- Binary modular exponentiation with explicit fuel (structural recursion on the fuel). -/
def powModAux : ℕ → ℕ → ℕ → ℕ → ℕ
  | 0, _, _, m => 1 % m
  | fuel + 1, b, e, m =>
    if e = 0 then 1 % m
    else
      let r := powModAux fuel (b * b % m) (e / 2) m
      if e % 2 = 1 then b * r % m else r

theorem powModAux_eq (fuel b e m : ℕ) (h : e < 2 ^ fuel) :
    powModAux fuel b e m = b ^ e % m := by
  induction fuel generalizing b e with
  | zero =>
    simp at h; subst h; simp [powModAux]
  | succ n ih =>
    unfold powModAux
    by_cases he : e = 0
    · simp [he]
    · simp only [he, if_false]
      have h2 : e / 2 < 2 ^ n := by
        rw [pow_succ] at h; omega
      rw [ih _ _ h2]
      have hdec : e = 2 * (e / 2) + e % 2 := (Nat.div_add_mod e 2).symm
      split_ifs with ho
      · conv_rhs => rw [hdec, ho, pow_add, pow_mul]
        simp [Nat.mul_mod, Nat.pow_mod, sq, Nat.mul_comm]
      · have h0 : e % 2 = 0 := by omega
        conv_rhs => rw [hdec, h0, add_zero, pow_mul]
        simp [Nat.pow_mod, sq, Nat.mul_mod]

/-- In `ZMod n`, a natural-number power is the cast of the binary modular power. -/
theorem zmod_pow_eq_powModAux (n a e : ℕ) (h : e < 2 ^ 256) :
    (a : ZMod n) ^ e = ((powModAux 256 a e n : ℕ) : ZMod n) := by
  rw [powModAux_eq _ _ _ _ h, ZMod.natCast_mod]; push_cast; rfl

theorem prime_dvd_prod_pow (fs : List (ℕ × ℕ)) (hprime : ∀ r ∈ fs, r.1.Prime) (q : ℕ)
    (hq : q.Prime) (h : q ∣ (fs.map fun r => r.1 ^ r.2).prod) : ∃ r ∈ fs, r.1 = q := by
  induction fs with
  | nil => simp only [List.map_nil, List.prod_nil, Nat.dvd_one] at h; exact absurd h hq.ne_one
  | cons r rs ih =>
    simp only [List.map_cons, List.prod_cons] at h
    rcases (Nat.Prime.dvd_mul hq).mp h with h1 | h1
    · have hr := hprime r (List.mem_cons_self ..)
      exact ⟨r, List.mem_cons_self .., ((Nat.prime_dvd_prime_iff_eq hq hr).mp
        (hq.dvd_of_dvd_pow h1)).symm⟩
    · obtain ⟨r', hr', e⟩ := ih (fun r hr => hprime r (List.mem_cons_of_mem _ hr)) h1
      exact ⟨r', List.mem_cons_of_mem _ hr', e⟩

/-- Every listed factor is prime. -/
def AllPrime : List (ℕ × ℕ) → Prop
  | [] => True
  | q :: qs => q.1.Prime ∧ AllPrime qs

theorem AllPrime.mem {fs : List (ℕ × ℕ)} (h : AllPrime fs) : ∀ r ∈ fs, r.1.Prime := by
  induction fs with
  | nil => simp
  | cons q qs ih =>
    intro r hr
    rcases List.mem_cons.mp hr with rfl | hr
    · exact h.1
    · exact ih h.2 r hr

/-- Lucas / Pratt primality certificate: `n - 1 = ∏ qᵢ^eᵢ` with all `qᵢ` prime,
`a^(n-1) ≡ 1` and `a^((n-1)/qᵢ) ≢ 1 (mod n)` for every `i`. -/
theorem lucas_cert (n a : ℕ) (fs : List (ℕ × ℕ)) (hn : 2 ≤ n) (hsize : n < 2 ^ 256)
    (hprod : n - 1 = (fs.map fun q => q.1 ^ q.2).prod)
    (hprime : AllPrime fs)
    (hpow : powModAux 256 a (n - 1) n = 1)
    (hq : fs.all (fun q => powModAux 256 a ((n - 1) / q.1) n != 1) = true) : n.Prime := by
  apply lucas_primality n (a : ZMod n)
  · rw [zmod_pow_eq_powModAux _ _ _ (by omega), hpow, Nat.cast_one]
  · intro q hqp hdvd hcontra
    rw [hprod] at hdvd
    obtain ⟨r, hr, rfl⟩ := prime_dvd_prod_pow fs hprime.mem q hqp hdvd
    have hne := (List.all_eq_true.mp hq) r hr
    have hlt : (n - 1) / r.1 < 2 ^ 256 := lt_of_le_of_lt (Nat.div_le_self _ _) (by omega)
    rw [zmod_pow_eq_powModAux _ _ _ hlt] at hcontra
    have hc : ((powModAux 256 a ((n - 1) / r.1) n : ℕ) : ZMod n) = ((1 : ℕ) : ZMod n) := by
      rw [hcontra, Nat.cast_one]
    rw [ZMod.natCast_eq_natCast_iff'] at hc
    have hm : powModAux 256 a ((n - 1) / r.1) n < n := by
      rw [powModAux_eq _ _ _ _ hlt]; exact Nat.mod_lt _ (by omega)
    rw [Nat.mod_eq_of_lt hm, Nat.mod_eq_of_lt (by omega)] at hc
    simp [hc] at hne

theorem prime_12048837557 : Nat.Prime 12048837557 :=
  lucas_cert 12048837557 2 [(2, 2), (7, 2), (661, 1), (93001, 1)] (by norm_num) (by norm_num)
    (by decide +kernel) ⟨by norm_num, by norm_num, by norm_num, by norm_num, trivial⟩
    (by decide +kernel) (by decide +kernel)

theorem prime_5156902474397 : Nat.Prime 5156902474397 :=
  lucas_cert 5156902474397 2 [(2, 2), (107, 1), (12048837557, 1)] (by norm_num) (by norm_num)
    (by decide +kernel) ⟨by norm_num, by norm_num, prime_12048837557, trivial⟩
    (by decide +kernel) (by decide +kernel)

theorem prime_1670836401704629 : Nat.Prime 1670836401704629 :=
  lucas_cert 1670836401704629 2 [(2, 2), (3, 4), (5156902474397, 1)] (by norm_num) (by norm_num)
    (by decide +kernel) ⟨by norm_num, by norm_num, prime_5156902474397, trivial⟩
    (by decide +kernel) (by decide +kernel)

theorem prime_65865678001877903 : Nat.Prime 65865678001877903 :=
  lucas_cert 65865678001877903 5 [(2, 1), (83, 1), (379, 1), (1637, 1), (639533339, 1)]
    (by norm_num) (by norm_num) (by decide +kernel)
    ⟨by norm_num, by norm_num, by norm_num, by norm_num, by norm_num, trivial⟩
    (by decide +kernel) (by decide +kernel)

theorem prime_13818364434197438864469338081 : Nat.Prime 13818364434197438864469338081 :=
  lucas_cert 13818364434197438864469338081 3
    [(2, 5), (5, 1), (823, 1), (1593227, 1), (65865678001877903, 1)]
    (by norm_num) (by norm_num) (by decide +kernel)
    ⟨by norm_num, by norm_num, by norm_num, by norm_num, prime_65865678001877903, trivial⟩
    (by decide +kernel) (by decide +kernel)

/-- BN254 scalar field modulus (`ark_bn254::Fr`, = `ark_ed_on_bn254::Fq`). -/
def p : ℕ := 21888242871839275222246405745257275088548364400416034343698204186575808495617

theorem p_prime : p.Prime :=
  lucas_cert p 5
    [(2, 28), (3, 2), (13, 1), (29, 1), (983, 1), (11003, 1), (237073, 1), (405928799, 1),
      (1670836401704629, 1), (13818364434197438864469338081, 1)]
    (by norm_num [p]) (by norm_num [p]) (by decide +kernel)
    ⟨by norm_num, by norm_num, by norm_num, by norm_num, by norm_num, by norm_num, by norm_num,
      by norm_num, prime_1670836401704629, prime_13818364434197438864469338081, trivial⟩
    (by decide +kernel) (by decide +kernel)

instance : Fact p.Prime := ⟨p_prime⟩

/-- The constraint field. -/
abbrev F := ZMod p

theorem p_gt_two : 2 < p := by norm_num [p]

theorem two_ne_zero_F : (2 : F) ≠ 0 := by
  intro h
  have : ((2 : ℕ) : F) = ((0 : ℕ) : F) := by simpa using h
  rw [ZMod.natCast_eq_natCast_iff'] at this
  norm_num [p] at this

/-- `COEFF_D` of `ark_ed_on_bn254::EdwardsConfig` (twisted Edwards form):
`168696 / 168700 mod p`. -/
def dNat : ℕ := 9706598848417545097372247223557719406784115219466060233080913168975159366771

/-- `COEFF_D` as a field element. -/
def d : F := (dNat : F)

/-- `COEFF_A = 1` (`Fq::ONE`) of `ark_ed_on_bn254::EdwardsConfig`. -/
def a : F := 1

/-- `d` really is `168696 / 168700` (i.e. `d * 168700 = 168696` in `F`). -/
theorem d_mul : d * 168700 = 168696 := by
  have h : ((dNat * 168700 : ℕ) : F) = ((168696 : ℕ) : F) := by
    rw [ZMod.natCast_eq_natCast_iff']; decide +kernel
  simpa [d] using h

theorem d_ne_zero : d ≠ 0 := by
  intro h
  have : ((dNat : ℕ) : F) = ((0 : ℕ) : F) := by simpa [d] using h
  rw [ZMod.natCast_eq_natCast_iff'] at this
  norm_num [dNat, p] at this

/-- Euler's criterion certificate: `d ^ ((p-1)/2) = -1`, computed by the kernel. -/
theorem d_pow_half : d ^ (p / 2) = -1 := by
  rw [d, zmod_pow_eq_powModAux _ _ _ (by norm_num [p])]
  have h : powModAux 256 dNat (p / 2) p = p - 1 := by decide +kernel
  rw [h, Nat.cast_sub (by norm_num [p]), ZMod.natCast_self, Nat.cast_one, zero_sub]

/-- `d` is not a square in `F` (Euler's criterion). -/
theorem d_not_square : ¬ IsSquare d := by
  rw [ZMod.euler_criterion p d_ne_zero, d_pow_half]
  intro h
  have h2 : (2 : F) = 0 := by linear_combination -h
  exact two_ne_zero_F h2

end Picus
