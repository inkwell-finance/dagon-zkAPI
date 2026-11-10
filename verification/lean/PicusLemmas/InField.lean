import PicusLemmas.R1CS
import Mathlib.Tactic.LinearCombination

/-!
# L-bits: `FpVar::to_bits_le` (254 bits + `Boolean::enforce_in_field_le`) is canonical

`toBitsLe base x` *generates* the exact constraint list that `ark-r1cs-std 0.5.0` emits for
`AllocatedFp::to_bits_le` on the BN254 scalar field (`fields/fp/mod.rs:500-545`,
`boolean/cmp.rs:24-94`, `boolean/and.rs`, `boolean/eq.rs`, `fields/fp/mod.rs:368-438`),
with the same wire-allocation order: bit `i` (little-endian) is wire `base + i`, fresh
wires are allocated from `base + 254` on, and `x` is the linear combination being
decomposed. The linkage script compares this list, constraint by constraint, against the
pinned `.r1cs` files.

Main theorem `toBitsLe_canonical`: every assignment satisfying the generated constraints
(with `w 0 = 1`) has `w (base + i) = bit i of (⟦x⟧.val)` for all `i < 254`.
-/

namespace Picus

/-! ## Generator (mirrors arkworks) -/

/-- `Boolean<F>`: a constant, or a variable given by a linear combination. -/
inductive BT
  | const : Bool → BT
  | var : LC → BT

def BT.lc : BT → LC
  | .const true => LC.one
  | .const false => []
  | .var l => l

def BT.val (w : ℕ → F) (b : BT) : F := b.lc.eval w

/-- Constraint-system state: next fresh wire and the constraints emitted so far. -/
structure St where
  next : ℕ
  cons : List Con

/-- `Boolean::_and` (`boolean/and.rs:10-19`) / `AllocatedBool::and` (`allocated.rs:105-119`). -/
def band (x y : BT) (s : St) : BT × St :=
  match x, y with
  | .const false, _ => (.const false, s)
  | _, .const false => (.const false, s)
  | .const true, y => (y, s)
  | x, .const true => (x, s)
  | .var a, .var b => (.var (LC.var s.next), ⟨s.next + 1, s.cons ++ [⟨a, b, LC.var s.next⟩]⟩)

def foldAnd : BT → List BT → St → BT × St
  | cur, [], s => (cur, s)
  | cur, b :: bs, s => foldAnd (band cur b s).1 bs (band cur b s).2

/-- `Boolean::kary_and` (`boolean/and.rs:51-70`). For more than three operands it is
`Σ bits == n` via `FpVar::is_eq` against the constant `n`, i.e. `!(n.is_neq(Σ bits))`. -/
def karyAnd (bits : List BT) (s : St) : BT × St :=
  match bits with
  | [] => (.const true, s)
  | b :: bs =>
    if bits.length ≤ 3 then foldAnd b bs s
    else
      let diff : LC := LC.const (bits.length : F) ++ LC.neg (bits.flatMap BT.lc)
      (.var (LC.one ++ (LC.var s.next).neg),
        ⟨s.next + 2, s.cons ++ [⟨diff, LC.var (s.next + 1), LC.var s.next⟩,
                                ⟨diff, LC.one ++ (LC.var s.next).neg, []⟩]⟩)

/-- `Boolean::enforce_equal(&Boolean::FALSE)` (`boolean/eq.rs:21-49`, condition `TRUE`).
The constant-`true` case is an arkworks synthesis error; it is modelled as `0·0 = 1`. -/
def enforceFalse (r : BT) (s : St) : St :=
  match r with
  | .const false => s
  | .const true => ⟨s.next, s.cons ++ [⟨[], [], LC.one⟩]⟩
  | .var l => ⟨s.next, s.cons ++ [⟨l, LC.one, []⟩]⟩

/-- `Boolean::enforce_kary_nand(&[l, a])` (`boolean/and.rs:105-107`). -/
def enforceNand (l a : BT) (s : St) : St :=
  enforceFalse (karyAnd [l, a] s).1 (karyAnd [l, a] s).2

/-- The main loop of `enforce_smaller_or_equal_than_le` (`boolean/cmp.rs:68-90`),
over the big-endian bits of the bound paired with the big-endian bit variables. -/
def loop : List (Bool × BT) → BT → List BT → St → List BT × St
  | [], _, cur, s => (cur, s)
  | (true, a) :: rest, lr, cur, s => loop rest lr (cur ++ [a]) s
  | (false, a) :: rest, lr, cur, s =>
    let r := if cur.isEmpty then (lr, s) else karyAnd (cur ++ [lr]) s
    loop rest r.1 [] (enforceNand r.1 a r.2)

/-- Bit `i` of `p - 1`, the bound used by `enforce_in_field_le`. -/
def pm1Bit (i : ℕ) : Bool := (p - 1).testBit i

/-- Big-endian pattern of `p - 1` (254 bits, no leading zeros), paired with the bit wires. -/
def inFieldPattern (base : ℕ) : List (Bool × BT) :=
  (List.range 254).reverse.map fun i => (pm1Bit i, BT.var (LC.var (base + i)))

/-- The full constraint list of `AllocatedFp::to_bits_le` for the linear combination `x`:
254 booleanity constraints `(1 - bᵢ)·bᵢ = 0` (`AllocatedBool::new_variable`), the packing
constraint `0·0 = Σ 2ⁱ·bᵢ - x`, then `enforce_in_field_le` (bound `p - 1`). -/
def toBitsLe (base : ℕ) (x : LC) : St :=
  let bitCons : List Con := (List.range 254).map fun i =>
    ⟨LC.one ++ (LC.var (base + i)).neg, LC.var (base + i), []⟩
  let sumLC : LC := ((List.range 254).map fun i => (base + i, (2 : F) ^ i)) ++ x.neg
  let s0 : St := ⟨base + 254, bitCons ++ [⟨[], [], sumLC⟩]⟩
  (loop (inFieldPattern base) (.const true) [] s0).2

/-! ## Soundness -/

def AllSat (w : ℕ → F) (s : St) : Prop := ∀ c ∈ s.cons, c.Sat w

/-- `s'` extends `s` by appending constraints. -/
def Grows (s s' : St) : Prop := ∃ δ, s'.cons = s.cons ++ δ

theorem Grows.refl (s : St) : Grows s s := ⟨[], by simp⟩

theorem Grows.trans {s1 s2 s3 : St} (h1 : Grows s1 s2) (h2 : Grows s2 s3) : Grows s1 s3 := by
  obtain ⟨δ1, e1⟩ := h1; obtain ⟨δ2, e2⟩ := h2
  exact ⟨δ1 ++ δ2, by rw [e2, e1, List.append_assoc]⟩

theorem AllSat.of_grows {w : ℕ → F} {s s' : St} (hg : Grows s s') (h : AllSat w s') :
    AllSat w s := by
  obtain ⟨δ, e⟩ := hg
  intro c hc; apply h; rw [e]; exact List.mem_append_left _ hc

theorem AllSat.last {w : ℕ → F} {s s' : St} {δ : List Con} (e : s'.cons = s.cons ++ δ)
    (h : AllSat w s') : ∀ c ∈ δ, c.Sat w := by
  intro c hc; apply h; rw [e]; exact List.mem_append_right _ hc

theorem band_grows (x y : BT) (s : St) : Grows s (band x y s).2 := by
  unfold band; split <;> first | exact Grows.refl _ | exact ⟨_, rfl⟩

theorem foldAnd_grows (bs : List BT) : ∀ (cur : BT) (s : St), Grows s (foldAnd cur bs s).2 := by
  induction bs with
  | nil => intro cur s; exact Grows.refl _
  | cons b bs ih => intro cur s; exact (band_grows cur b s).trans (ih _ _)

theorem karyAnd_grows (bits : List BT) (s : St) : Grows s (karyAnd bits s).2 := by
  unfold karyAnd; split
  · exact Grows.refl _
  · split
    · exact foldAnd_grows _ _ _
    · exact ⟨_, rfl⟩

theorem enforceFalse_grows (r : BT) (s : St) : Grows s (enforceFalse r s) := by
  unfold enforceFalse; split <;> first | exact Grows.refl _ | exact ⟨_, rfl⟩

theorem enforceNand_grows (l a : BT) (s : St) : Grows s (enforceNand l a s) :=
  (karyAnd_grows _ s).trans (enforceFalse_grows _ _)

theorem loop_grows (pat : List (Bool × BT)) :
    ∀ (lr : BT) (cur : List BT) (s : St), Grows s (loop pat lr cur s).2 := by
  induction pat with
  | nil => intro lr cur s; exact Grows.refl _
  | cons q rest ih =>
    intro lr cur s
    obtain ⟨qb, qa⟩ := q
    cases qb with
    | true => exact ih _ _ _
    | false =>
      simp only [loop]
      refine Grows.trans ?_ ((enforceNand_grows _ _ _).trans (ih _ _ _))
      split
      · exact Grows.refl _
      · exact karyAnd_grows _ _

/-- `loop` leaves no pending run when the bound's last (least significant) bit is `0`. -/
theorem loop_end (pat : List (Bool × BT)) :
    ∀ (lr : BT) (cur : List BT) (s : St), (pat.map Prod.fst).getLast? = some false →
    (loop pat lr cur s).1 = [] := by
  induction pat with
  | nil => intro lr cur s h; simp at h
  | cons q rest ih =>
    intro lr cur s h
    obtain ⟨qb, qa⟩ := q
    by_cases hr : rest = []
    · subst hr
      simp at h; subst h
      simp [loop]
    · have h' : (rest.map Prod.fst).getLast? = some false := by
        rw [List.map_cons, List.getLast?_cons] at h
        have : (rest.map Prod.fst) ≠ [] := by simpa using hr
        rw [List.getLast?_eq_getLast this] at h ⊢
        simpa [List.getLastD_eq_getLast?, List.getLast?_eq_getLast this] using h
      cases qb with
      | true => exact ih _ _ _ h'
      | false => exact ih _ _ _ h'

def IsB (v : F) : Prop := v = 0 ∨ v = 1

/-- Natural-number value of a boolean field element. -/
def bn (v : F) : ℕ := if v = 1 then 1 else 0

theorem one_ne_zero_F : (1 : F) ≠ 0 := one_ne_zero

theorem bn_cast {v : F} (h : IsB v) : ((bn v : ℕ) : F) = v := by
  rcases h with rfl | rfl <;> simp [bn]

theorem bn_le (v : F) : bn v ≤ 1 := by unfold bn; split_ifs <;> omega

theorem bn_eq_one {v : F} : bn v = 1 ↔ v = 1 := by unfold bn; split_ifs <;> simp_all

section
variable {w : ℕ → F} (h0 : w 0 = 1)
include h0

theorem BT.val_true : (BT.const true).val w = 1 := by simp [BT.val, BT.lc, LC.eval_one w h0]

theorem band_sound (x y : BT) (s : St) (hs : AllSat w (band x y s).2) :
    (band x y s).1.val w = x.val w * y.val w := by
  have hT := BT.val_true h0
  cases x with
  | const bx =>
    cases bx
    · simp [band, BT.val, BT.lc]
    · cases y with
      | const by_ =>
        cases by_
        · simp [band, BT.val, BT.lc]
        · simp only [band]; rw [hT, one_mul]
      | var b => simp only [band]; rw [hT, one_mul]
  | var a =>
    cases y with
    | const by_ =>
      cases by_
      · simp [band, BT.val, BT.lc]
      · simp only [band]; rw [hT, mul_one]
    | var b =>
      have := AllSat.last (s := s) (δ := [⟨a, b, LC.var s.next⟩]) rfl hs _
        (List.mem_singleton_self _)
      simp only [Con.Sat, LC.eval_var] at this
      simp only [band, BT.val, BT.lc, LC.eval_var]
      exact this.symm

theorem foldAnd_sound (bs : List BT) : ∀ (cur : BT) (s : St), AllSat w (foldAnd cur bs s).2 →
    (foldAnd cur bs s).1.val w = cur.val w * (bs.map (BT.val w)).prod := by
  induction bs with
  | nil => intro cur s _; simp [foldAnd]
  | cons b bs ih =>
    intro cur s hs
    simp only [foldAnd] at hs ⊢
    have hv1 := ih _ _ hs
    have hv2 := band_sound h0 cur b s (AllSat.of_grows (foldAnd_grows _ _ _) hs)
    rw [hv1, hv2, List.map_cons, List.prod_cons]; ring

omit h0 in
theorem prod_isB (l : List F) (h : ∀ v ∈ l, IsB v) :
    IsB l.prod ∧ (l.prod = 1 ↔ ∀ v ∈ l, v = 1) := by
  induction l with
  | nil => exact ⟨Or.inr rfl, by simp⟩
  | cons v l ih =>
    obtain ⟨ih1, ih2⟩ := ih (fun u hu => h u (List.mem_cons_of_mem _ hu))
    rcases h v (List.mem_cons_self ..) with rfl | rfl
    · refine ⟨Or.inl (by simp), ?_⟩
      simp only [List.prod_cons, zero_mul, List.mem_cons, forall_eq_or_imp]
      constructor
      · intro h; exact absurd h.symm one_ne_zero_F
      · intro h; exact absurd h.1.symm one_ne_zero_F
    · simp only [List.prod_cons, one_mul, List.mem_cons, forall_eq_or_imp, true_and]
      exact ⟨ih1, ih2⟩

omit h0 in
/-- A list of booleans sums to its length iff all are one (no wrap-around: length < p). -/
theorem sum_isB (l : List F) (h : ∀ v ∈ l, IsB v) (hl : l.length < p) :
    l.sum = (l.length : F) ↔ ∀ v ∈ l, v = 1 := by
  have key : ∀ l : List F, (∀ v ∈ l, IsB v) →
      ∃ k : ℕ, k ≤ l.length ∧ l.sum = (k : F) ∧ (k = l.length ↔ ∀ v ∈ l, v = 1) := by
    intro l h
    induction l with
    | nil => exact ⟨0, le_refl _, by simp, by simp⟩
    | cons v l ih =>
      obtain ⟨k, hk, hs, hiff⟩ := ih (fun u hu => h u (List.mem_cons_of_mem _ hu))
      rcases h v (List.mem_cons_self ..) with rfl | rfl
      · refine ⟨k, by simp; omega, by simp [hs], ?_⟩
        simp only [List.length_cons, List.mem_cons, forall_eq_or_imp]
        constructor
        · intro h; omega
        · intro h; exact absurd h.1.symm one_ne_zero_F
      · refine ⟨k + 1, by simp; omega, by simp [hs, add_comm], ?_⟩
        simp only [List.length_cons, List.mem_cons, forall_eq_or_imp, true_and]
        constructor
        · intro h; exact hiff.mp (by omega)
        · intro h; rw [hiff.mpr h]
  obtain ⟨k, hk, hs, hiff⟩ := key l h
  rw [hs, ← hiff]
  constructor
  · intro he
    have := (ZMod.natCast_eq_natCast_iff' k l.length p).mp he
    rwa [Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt hl] at this
  · intro he; rw [he]

omit h0 in
theorem isNeq_core {δ m ne : F} (h1 : δ * m = ne) (h2 : δ * (1 + -ne) = 0) :
    ne = if δ = 0 then 0 else 1 := by
  split_ifs with hδ
  · rw [← h1, hδ, zero_mul]
  · rcases mul_eq_zero.mp h2 with h | h
    · exact absurd h hδ
    · linear_combination -h

theorem karyAnd_sound (bits : List BT) (s : St) (hne : bits ≠ []) (hlen : bits.length < p)
    (hb : ∀ b ∈ bits, IsB (b.val w)) (hs : AllSat w (karyAnd bits s).2) :
    IsB ((karyAnd bits s).1.val w) ∧
      ((karyAnd bits s).1.val w = 1 ↔ ∀ b ∈ bits, b.val w = 1) := by
  match bits, hne with
  | b :: bs, _ =>
    have hbm : ∀ v ∈ (b :: bs).map (BT.val w), IsB v := by
      intro v hv
      obtain ⟨u, hu, rfl⟩ := List.mem_map.mp hv
      exact hb u hu
    by_cases hl : (b :: bs).length ≤ 3
    · simp only [karyAnd, if_pos hl] at hs ⊢
      have hv := foldAnd_sound h0 bs b s hs
      have hprod := prod_isB ((b :: bs).map (BT.val w)) hbm
      simp only [List.map_cons, List.prod_cons] at hprod
      rw [hv]
      refine ⟨hprod.1, ?_⟩
      rw [hprod.2]; simp
    · simp only [karyAnd, if_neg hl] at hs ⊢
      have hl2 := AllSat.last (s := s) rfl hs
      have c1 := hl2 _ (List.mem_cons_self ..)
      have c2 := hl2 _ (List.mem_cons_of_mem _ (List.mem_singleton_self _))
      simp only [Con.Sat, LC.eval_append, LC.eval_const w h0, LC.eval_neg, LC.eval_var,
        LC.eval_flatMap, LC.eval_one w h0, LC.eval_nil] at c1 c2
      have hsum := sum_isB ((b :: bs).map (BT.val w)) hbm (by simpa using hlen)
      simp only [List.length_map] at hsum
      simp only [BT.val, BT.lc, LC.eval_append, LC.eval_one w h0, LC.eval_neg, LC.eval_var]
      have hval : ((b :: bs).map fun x => x.lc.eval w) = (b :: bs).map (BT.val w) := rfl
      rw [hval] at c1 c2
      set δ := ((b :: bs).length : F) - ((b :: bs).map (BT.val w)).sum with hδ
      have c1' : δ * w (s.next + 1) = w s.next := by rw [hδ]; linear_combination c1
      have c2' : δ * (1 + -w s.next) = 0 := by rw [hδ]; linear_combination c2
      have hne' := isNeq_core c1' c2'
      by_cases h : δ = 0
      · rw [if_pos h] at hne'
        rw [hne']
        refine ⟨Or.inr (by ring), ?_⟩
        simp only [neg_zero, add_zero, true_iff]
        have : ((b :: bs).map (BT.val w)).sum = ((b :: bs).length : F) := by
          linear_combination -h
        intro u hu
        exact (hsum.mp this) _ (List.mem_map_of_mem hu)
      · rw [if_neg h] at hne'
        rw [hne']
        refine ⟨Or.inl (by ring), ?_⟩
        constructor
        · intro h1; exact absurd (by linear_combination -h1) one_ne_zero_F
        · intro hall
          exfalso; apply h
          have : ((b :: bs).map (BT.val w)).sum = ((b :: bs).length : F) := by
            apply hsum.mpr
            intro v hv
            obtain ⟨u, hu, rfl⟩ := List.mem_map.mp hv
            exact hall u hu
          rw [hδ, this, sub_self]

theorem enforceNand_sound (l a : BT) (s : St) (hs : AllSat w (enforceNand l a s)) :
    ¬ (l.val w = 1 ∧ a.val w = 1) := by
  unfold enforceNand at hs
  have hk : karyAnd [l, a] s = band l a s := by
    simp [karyAnd, foldAnd]
  rw [hk] at hs
  have hs1 : AllSat w (band l a s).2 := AllSat.of_grows (enforceFalse_grows _ _) hs
  have hv := band_sound h0 l a s hs1
  -- the result of `band` is forced to 0
  have hz : (band l a s).1.val w = 0 := by
    generalize (band l a s) = r at hs
    obtain ⟨r1, r2⟩ := r
    cases r1 with
    | const b =>
      cases b
      · simp [BT.val, BT.lc]
      · have := AllSat.last (s := r2) rfl hs _ (List.mem_singleton_self _)
        simp [Con.Sat, LC.eval_one w h0] at this
    | var l' =>
      have := AllSat.last (s := r2) rfl hs _ (List.mem_singleton_self _)
      simp only [Con.Sat, LC.eval_one w h0, mul_one, LC.eval_nil] at this
      simpa [BT.val, BT.lc] using this
  rintro ⟨h1, h2⟩
  rw [hz, h1, h2, one_mul] at hv
  exact one_ne_zero_F hv.symm

/-! ### Natural-number bookkeeping -/

/-- Big-endian fold `acc ↦ 2·acc + b`. -/
def beFold (acc : ℕ) (l : List ℕ) : ℕ := l.foldl (fun a b => 2 * a + b) acc

omit h0 in
theorem beFold_cons (acc b : ℕ) (l : List ℕ) : beFold acc (b :: l) = beFold (2 * acc + b) l := rfl

omit h0 in
theorem beFold_acc (l : List ℕ) : ∀ acc, beFold acc l = acc * 2 ^ l.length + beFold 0 l := by
  induction l with
  | nil => intro acc; simp [beFold]
  | cons b l ih =>
    intro acc
    rw [beFold_cons, beFold_cons, ih (2 * acc + b), ih (2 * 0 + b), List.length_cons, pow_succ]
    ring

omit h0 in
theorem beFold_append1 (l : List ℕ) (b acc : ℕ) :
    beFold acc (l ++ [b]) = 2 * beFold acc l + b := by
  simp [beFold, List.foldl_append]

omit h0 in
theorem beFold_bits (l : List ℕ) (hl : ∀ b ∈ l, b ≤ 1) :
    beFold 0 l + 1 ≤ 2 ^ l.length ∧ (beFold 0 l + 1 = 2 ^ l.length ↔ ∀ b ∈ l, b = 1) := by
  induction l with
  | nil => simp [beFold]
  | cons b l ih =>
    obtain ⟨ih1, ih2⟩ := ih (fun c hc => hl c (List.mem_cons_of_mem _ hc))
    have hb := hl b (List.mem_cons_self ..)
    have e : beFold 0 (b :: l) = b * 2 ^ l.length + beFold 0 l := by
      rw [beFold_cons, beFold_acc]; simp
    rw [e, List.length_cons, pow_succ]
    simp only [List.mem_cons, forall_eq_or_imp]
    have hp : 1 ≤ 2 ^ l.length := Nat.one_le_two_pow
    interval_cases b
    · refine ⟨by omega, ?_⟩; simp; omega
    · refine ⟨by omega, ?_⟩; simp only [true_and]; rw [← ih2]; omega

omit h0 in
theorem zero_step {Db Dp b : ℕ} {r : Prop} (hD : Db ≤ Dp) (hr : r ↔ Db = Dp) (hb : b ≤ 1)
    (hnand : ¬ (r ∧ b = 1)) : 2 * Db + b ≤ 2 * Dp + 0 ∧ (r ↔ 2 * Db + b = 2 * Dp + 0) := by
  by_cases h : Db = Dp
  · have : b = 0 := by have := hr.mpr h; by_contra hc; exact hnand ⟨this, by omega⟩
    subst this; exact ⟨by omega, by rw [hr]; omega⟩
  · have hlt : Db < Dp := lt_of_le_of_ne hD h
    exact ⟨by omega, by rw [hr]; omega⟩

/-- Loop invariant of `enforce_smaller_or_equal_than_le`: the bits read big-endian never
exceed the bound. `Db`/`Dp` are the values of the completed prefix, `cur` the pending run. -/
theorem loop_sound (pat : List (Bool × BT)) :
    ∀ (lr : BT) (cur : List BT) (s : St) (Db Dp : ℕ),
    (∀ q ∈ pat, IsB (q.2.val w)) → (∀ c ∈ cur, IsB (c.val w)) → IsB (lr.val w) →
    cur.length + pat.length + 1 < p →
    Db ≤ Dp → (lr.val w = 1 ↔ Db = Dp) →
    AllSat w (loop pat lr cur s).2 → (loop pat lr cur s).1 = [] →
      beFold (Db * 2 ^ cur.length + beFold 0 (cur.map fun c => bn (c.val w)))
          (pat.map fun q => bn (q.2.val w)) ≤
        beFold (Dp * 2 ^ cur.length + (2 ^ cur.length - 1))
          (pat.map fun q => if q.1 then 1 else 0) := by
  induction pat with
  | nil =>
    intro lr cur s Db Dp _ _ _ _ hD _ hs hend
    simp only [loop] at hs hend
    subst hend
    simp [beFold]; exact hD
  | cons q rest ih =>
    intro lr cur s Db Dp hpat hcur hlr hlen hD hr hs hend
    obtain ⟨qb, qa⟩ := q
    have hqa : IsB (qa.val w) := hpat _ (List.mem_cons_self ..)
    have hrest : ∀ q ∈ rest, IsB (q.2.val w) := fun q hq => hpat q (List.mem_cons_of_mem _ hq)
    have hp1 : 1 ≤ 2 ^ cur.length := Nat.one_le_two_pow
    cases qb with
    | true =>
      simp only [loop] at hs hend
      have hcur' : ∀ c ∈ cur ++ [qa], IsB (c.val w) := by
        intro c hc
        rcases List.mem_append.mp hc with hc | hc
        · exact hcur c hc
        · rw [List.mem_singleton.mp hc]; exact hqa
      have hv := ih lr (cur ++ [qa]) s Db Dp hrest hcur' hlr
        (by simp only [List.length_append, List.length_cons, List.length_nil] at hlen ⊢; omega)
        hD hr hs hend
      simp only [List.map_cons, beFold_cons, if_true]
      rw [List.map_append, List.map_singleton, beFold_append1, List.length_append,
        List.length_singleton, pow_succ] at hv
      have e1 : Db * (2 ^ cur.length * 2) + (2 * beFold 0 (cur.map fun c => bn (c.val w)) +
          bn (qa.val w)) =
          2 * (Db * 2 ^ cur.length + beFold 0 (cur.map fun c => bn (c.val w))) +
          bn (qa.val w) := by ring
      have e2 : Dp * (2 ^ cur.length * 2) + (2 ^ cur.length * 2 - 1) =
          2 * (Dp * 2 ^ cur.length + (2 ^ cur.length - 1)) + 1 := by
        have : 2 ^ cur.length * 2 - 1 = 2 * (2 ^ cur.length - 1) + 1 := by omega
        rw [this]; ring
      rw [e1, e2] at hv
      exact hv
    | false =>
      simp only [loop] at hs hend
      set R := beFold 0 (cur.map fun c => bn (c.val w)) with hR
      set r := (if cur.isEmpty then (lr, s) else karyAnd (cur ++ [lr]) s) with hr_def
      have hsN : AllSat w (enforceNand r.1 qa r.2) := AllSat.of_grows (loop_grows _ _ _ _) hs
      have hsR : AllSat w r.2 := AllSat.of_grows (enforceNand_grows _ _ _) hsN
      have hcb : ∀ b ∈ cur.map (fun c => bn (c.val w)), b ≤ 1 := by
        intro b hb; obtain ⟨c, _, rfl⟩ := List.mem_map.mp hb; exact bn_le _
      have hbits := beFold_bits _ hcb
      simp only [List.length_map] at hbits
      have hDle : Db * 2 ^ cur.length + R ≤ Dp * 2 ^ cur.length + (2 ^ cur.length - 1) := by
        have := Nat.mul_le_mul_right (2 ^ cur.length) hD
        omega
      -- semantics of the new `last_run`
      have hRs : IsB (r.1.val w) ∧
          (r.1.val w = 1 ↔ Db * 2 ^ cur.length + R = Dp * 2 ^ cur.length + (2 ^ cur.length - 1)) := by
        by_cases hce : cur = []
        · subst hce
          simp only [hr_def, List.isEmpty_nil, if_true]
          simp only [hR, List.length_nil, pow_zero, mul_one, List.map_nil, Nat.sub_self,
            add_zero]
          simp only [beFold, List.foldl_nil, add_zero]
          exact ⟨hlr, hr⟩
        · have hce' : cur.isEmpty = false := by simp [hce]
          simp only [hr_def, hce', Bool.false_eq_true, if_false] at hsR ⊢
          have hall : ∀ b ∈ cur ++ [lr], IsB (b.val w) := by
            intro b hb
            rcases List.mem_append.mp hb with hb | hb
            · exact hcur b hb
            · rw [List.mem_singleton.mp hb]; exact hlr
          obtain ⟨hB, hiff⟩ := karyAnd_sound h0 _ s (by simp)
            (by simp only [List.length_append, List.length_cons, List.length_nil] at hlen ⊢
                omega) hall hsR
          refine ⟨hB, ?_⟩
          rw [hiff]
          simp only [List.mem_append, List.mem_singleton]
          constructor
          · intro hall1
            have hl1 : lr.val w = 1 := hall1 lr (Or.inr rfl)
            have hc1 : ∀ b ∈ cur.map (fun c => bn (c.val w)), b = 1 := by
              intro b hb; obtain ⟨c, hc, rfl⟩ := List.mem_map.mp hb
              exact bn_eq_one.mpr (hall1 c (Or.inl hc))
            have h2 := hbits.2.mpr hc1
            have h3 := hr.mp hl1
            subst h3; omega
          · intro heq
            have hDeq : Db = Dp ∧ R + 1 = 2 ^ cur.length := by
              rcases Nat.lt_or_ge Db Dp with hlt | hge
              · exfalso
                have := Nat.mul_le_mul_right (2 ^ cur.length) (Nat.succ_le_of_lt hlt)
                rw [Nat.succ_mul] at this
                omega
              · have hDD : Db = Dp := le_antisymm hD hge
                subst hDD; exact ⟨rfl, by omega⟩
            intro b hb
            rcases hb with hb | rfl
            · exact bn_eq_one.mp (hbits.2.mp hDeq.2 _ (List.mem_map_of_mem hb))
            · exact hr.mpr hDeq.1
      have hnand := enforceNand_sound h0 r.1 qa r.2 hsN
      have hz := zero_step hDle hRs.2 (bn_le (qa.val w))
        (fun ⟨h1, h2⟩ => hnand ⟨h1, bn_eq_one.mp h2⟩)
      have hv := ih r.1 [] (enforceNand r.1 qa r.2) _ _ hrest (by simp) hRs.1
        (by simp only [List.length_cons, List.length_nil] at hlen ⊢; omega) hz.1
        hz.2 hs hend
      simp only [List.length_nil, pow_zero, mul_one, List.map_nil, Nat.sub_self, add_zero]
        at hv
      simp only [beFold, List.foldl_nil, add_zero] at hv
      simp only [List.map_cons, beFold_cons, Bool.false_eq_true, if_false]
      exact hv

end

/-! ### Assembling the theorem -/

theorem beFold_range (f : ℕ → ℕ) (n : ℕ) :
    beFold 0 ((List.range n).reverse.map f) = ((List.range n).map fun i => f i * 2 ^ i).sum := by
  induction n with
  | zero => simp [beFold]
  | succ n ih =>
    rw [List.range_succ, List.reverse_append, List.reverse_singleton, List.singleton_append,
      List.map_cons, beFold_cons, beFold_acc, List.length_map, List.length_reverse,
      List.length_range, ih, List.map_append, List.sum_append]
    simp; ring

theorem pattern_value :
    beFold 0 ((List.range 254).reverse.map fun i => if pm1Bit i then 1 else 0) = p - 1 := by
  decide +kernel

theorem pattern_last : ((List.range 254).reverse.map pm1Bit).getLast? = some false := by
  decide +kernel

theorem testBit_sum (g : ℕ → ℕ) (hg : ∀ j, g j ≤ 1) (n : ℕ) :
    ((List.range n).map fun j => g j * 2 ^ j).sum < 2 ^ n ∧
    ∀ i < n, ((List.range n).map fun j => g j * 2 ^ j).sum.testBit i = decide (g i = 1) := by
  induction n with
  | zero => simp
  | succ n ih =>
    obtain ⟨ih1, ih2⟩ := ih
    rw [List.range_succ, List.map_append, List.sum_append]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, add_zero]
    have hgn := hg n
    refine ⟨by rw [pow_succ]; interval_cases (g n) <;> omega, ?_⟩
    intro i hi
    rw [add_comm, mul_comm, Nat.testBit_two_pow_mul_add _ ih1]
    split_ifs with hin
    · exact ih2 i hin
    · have : i = n := by omega
      subst this
      simp only [Nat.sub_self, Nat.testBit_zero]
      interval_cases (g i) <;> simp

/-- **L-bits.** Every assignment satisfying the constraints that `FpVar::to_bits_le` emits
for the linear combination `x` (254 boolean bits, packing, `enforce_in_field_le`) assigns to
bit wire `base + i` exactly bit `i` of the canonical representative `⟦x⟧.val < p`. -/
theorem toBitsLe_canonical (base : ℕ) (x : LC) (w : ℕ → F) (h0 : w 0 = 1)
    (hsat : AllSat w (toBitsLe base x)) (i : ℕ) (hi : i < 254) :
    w (base + i) = if (x.eval w).val.testBit i then 1 else 0 := by
  -- the initial state (booleanity + packing constraints)
  set bitCons : List Con := (List.range 254).map fun i =>
    ⟨LC.one ++ (LC.var (base + i)).neg, LC.var (base + i), []⟩ with hbitCons
  set sumLC : LC := ((List.range 254).map fun i => (base + i, (2 : F) ^ i)) ++ x.neg with hsumLC
  set s0 : St := ⟨base + 254, bitCons ++ [⟨[], [], sumLC⟩]⟩ with hs0
  have hs0sat : AllSat w s0 := AllSat.of_grows (loop_grows _ _ _ _) hsat
  -- booleanity
  have hB : ∀ j < 254, IsB (w (base + j)) := by
    intro j hj
    have := hs0sat ⟨LC.one ++ (LC.var (base + j)).neg, LC.var (base + j), []⟩
      (List.mem_append_left _ (List.mem_map.mpr ⟨j, List.mem_range.mpr hj, rfl⟩))
    simp only [Con.Sat, LC.eval_append, LC.eval_one w h0, LC.eval_neg, LC.eval_var,
      LC.eval_nil] at this
    rcases mul_eq_zero.mp this with h | h
    · right; linear_combination -h
    · left; exact h
  -- packing
  have hpack : x.eval w = ((List.range 254).map fun j => (2 : F) ^ j * w (base + j)).sum := by
    have := hs0sat ⟨[], [], sumLC⟩ (List.mem_append_right _ (List.mem_singleton_self _))
    simp only [Con.Sat, LC.eval_nil, mul_zero, hsumLC, LC.eval_append, LC.eval_neg] at this
    have e : LC.eval w ((List.range 254).map fun i => (base + i, (2 : F) ^ i)) =
        ((List.range 254).map fun j => (2 : F) ^ j * w (base + j)).sum := by
      simp [LC.eval, List.map_map, Function.comp_def]
    rw [e] at this
    linear_combination this
  -- the comparison against p - 1
  set g : ℕ → ℕ := fun j => if j < 254 then bn (w (base + j)) else 0 with hg
  have hg1 : ∀ j, g j ≤ 1 := by intro j; simp only [hg]; split_ifs <;> simp [bn_le]
  have hpat_vals : (inFieldPattern base).map (fun q => bn (q.2.val w)) =
      (List.range 254).reverse.map g := by
    simp only [inFieldPattern, List.map_map]
    apply List.map_congr_left
    intro j hj
    have : j < 254 := by simpa using hj
    simp [hg, this, BT.val, BT.lc]
  have hpat_bits : (inFieldPattern base).map (fun q => if q.1 then 1 else 0) =
      (List.range 254).reverse.map (fun i => if pm1Bit i then 1 else 0) := by
    simp [inFieldPattern, List.map_map, Function.comp_def]
  have hpat_fst : (inFieldPattern base).map Prod.fst = (List.range 254).reverse.map pm1Bit := by
    simp [inFieldPattern, List.map_map, Function.comp_def]
  have hle := loop_sound h0 (inFieldPattern base) (.const true) [] s0 0 0
    (by
      intro q hq
      simp only [inFieldPattern, List.mem_map, List.mem_reverse, List.mem_range] at hq
      obtain ⟨j, hj, rfl⟩ := hq
      simpa [BT.val, BT.lc] using hB j hj)
    (by simp) (Or.inr (BT.val_true h0))
    (by simp [inFieldPattern, p])
    (le_refl _) (by simp [BT.val_true h0])
    hsat (loop_end _ _ _ _ (by rw [hpat_fst]; exact pattern_last))
  simp only [List.length_nil, pow_zero, mul_one, List.map_nil, Nat.sub_self, add_zero] at hle
  simp only [beFold, List.foldl_nil] at hle
  rw [← beFold, ← beFold, hpat_vals, hpat_bits, pattern_value, beFold_range] at hle
  -- value of the bits
  set N := ((List.range 254).map fun j => g j * 2 ^ j).sum with hN
  have hNp : N < p := by
    have : 1 ≤ p := by norm_num [p]
    omega
  have hcast : x.eval w = (N : F) := by
    rw [hpack, hN]
    push_cast [Nat.cast_list_sum]
    simp only [List.map_map]
    apply congrArg List.sum
    apply List.map_congr_left
    intro j hj
    have hj' : j < 254 := by simpa using hj
    simp only [Function.comp_apply, hg, if_pos hj']
    push_cast
    rw [bn_cast (hB j hj')]; ring
  have hval : (x.eval w).val = N := by
    rw [hcast, ZMod.val_natCast, Nat.mod_eq_of_lt hNp]
  rw [hval, ((testBit_sum g hg1 254).2 i hi)]
  have hgi : g i = bn (w (base + i)) := by simp [hg, hi]
  rw [hgi]
  rcases hB i hi with h | h <;> simp [h, bn, one_ne_zero_F.symm]

end Picus
