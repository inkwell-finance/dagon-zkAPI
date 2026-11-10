import PicusLemmas.Field
import Mathlib.Tactic.LinearCombination
import Mathlib.Tactic.FieldSimp

/-!
# L-EC: completeness of the arkworks twisted-Edwards add / double gadgets on Baby Jubjub

Curve: `a·x² + y² = 1 + d·x²·y²` with `a = 1` (`COEFF_A = Fq::ONE`) and
`d = 168696/168700` (`COEFF_D`), exactly the twisted-Edwards form used by
`ark_ed_on_bn254::EdwardsConfig` and by `ark-r1cs-std 0.5.0` `AffineVar`.

* `add_denoms_ne_zero`: for on-curve inputs, `1 ± d·(x1·y2)·(x2·y1) ≠ 0`
  (Bernstein–Lange completeness; `a = 1` is a square, `d` is a non-square — `d_not_square`).
* `add_gadget`: the six R1CS relations of `AffineVar + AffineVar`
  (`twisted_edwards/mod.rs:707-765`) force both denominators to be non-zero, determine
  `(x3, y3)` uniquely (the Edwards sum) and put it on the curve.
* `dbl_gadget`: the same for `double_in_place` (`twisted_edwards/mod.rs:474-516`).
* `onCurve_of_gadget`: the on-curve check of `new_variable_omit_prime_order_check`
  (`twisted_edwards/mod.rs:438-447`) is the curve equation.
-/

namespace Picus

/-- The twisted Edwards curve equation of `ark_ed_on_bn254` (`a·x² + y² = 1 + d·x²·y²`). -/
def OnCurve (x y : F) : Prop := a * x ^ 2 + y ^ 2 = 1 + d * x ^ 2 * y ^ 2

/-- The on-curve gadget `(d·x2 - 1) · y2 = a·x2 - 1` with `x2 = x·x`, `y2 = y·y`
is equivalent to the curve equation. -/
theorem onCurve_of_gadget {x y x2 y2 : F} (hx2 : x * x = x2) (hy2 : y * y = y2) :
    (d * x2 - 1) * y2 = a * x2 - 1 ↔ OnCurve x y := by
  subst hx2 hy2
  unfold OnCurve
  constructor <;> intro h <;> linear_combination -h

/-- Key step of the completeness proof: if `e² = 1` and `d·x1·y1·x2·y2 = e` for two
on-curve points, then `d` is a square — impossible. -/
theorem no_exceptional {x1 y1 x2 y2 e : F} (h1 : OnCurve x1 y1) (h2 : OnCurve x2 y2)
    (he : e ^ 2 = 1) (hV : d * x1 * y1 * x2 * y2 = e) : False := by
  unfold OnCurve at h1 h2
  simp only [a, one_mul] at h1 h2
  have hne : x1 * y1 * x2 * y2 ≠ 0 := by
    intro h0
    have : e = 0 := by rw [← hV]; linear_combination d * h0
    rw [this] at he; norm_num at he
  have hx1 : x1 ≠ 0 := by intro h; apply hne; simp [h]
  have hy1 : y1 ≠ 0 := by intro h; apply hne; simp [h]
  have hx2 : x2 ≠ 0 := by intro h; apply hne; simp [h]
  -- (x1 + e·y1)² = d·x1²·y1²·(x2 + y2)²  and  (x1 - e·y1)² = d·x1²·y1²·(x2 - y2)²
  have iA : (x1 + e * y1) ^ 2 = d * x1 ^ 2 * y1 ^ 2 * (x2 + y2) ^ 2 := by
    linear_combination h1 - d * x1 ^ 2 * y1 ^ 2 * h2 + (y1 ^ 2 - 1) * he
      - (d * x1 * y1 * x2 * y2 + e + 2 * x1 * y1) * hV
  have iB : (x1 - e * y1) ^ 2 = d * x1 ^ 2 * y1 ^ 2 * (x2 - y2) ^ 2 := by
    linear_combination h1 - d * x1 ^ 2 * y1 ^ 2 * h2 + (y1 ^ 2 - 1) * he
      - (d * x1 * y1 * x2 * y2 + e - 2 * x1 * y1) * hV
  have sq_of : ∀ s t : F, t ≠ 0 → s ^ 2 = d * x1 ^ 2 * y1 ^ 2 * t ^ 2 → IsSquare d := by
    intro s t ht hst
    refine ⟨s / (x1 * y1 * t), ?_⟩
    field_simp
    linear_combination -hst
  by_cases hp : x2 + y2 = 0
  · by_cases hm : x2 - y2 = 0
    · apply hx2
      have h2x : (2 : F) * x2 = 0 := by linear_combination hp + hm
      rcases mul_eq_zero.mp h2x with h | h
      · exact absurd h two_ne_zero_F
      · exact h
    · exact d_not_square (sq_of _ _ hm iB)
  · exact d_not_square (sq_of _ _ hp iA)

/-- **L-EC (completeness).** For on-curve inputs the two denominators of the
twisted-Edwards addition law, in the form `1 ± d·(x1·y2)·(x2·y1)` used by the gadget
(`v2 = v0·v1·d`, `v0 = x1·y2`, `v1 = x2·y1`), are non-zero. -/
theorem add_denoms_ne_zero {x1 y1 x2 y2 : F} (h1 : OnCurve x1 y1) (h2 : OnCurve x2 y2) :
    1 + d * ((x1 * y2) * (x2 * y1)) ≠ 0 ∧ 1 - d * ((x1 * y2) * (x2 * y1)) ≠ 0 := by
  constructor
  · intro h
    exact no_exceptional (e := -1) h1 h2 (by ring) (by linear_combination h)
  · intro h
    exact no_exceptional (e := 1) h1 h2 (by ring) (by linear_combination -h)

/-- Closure: the affine Edwards sum of two on-curve points is on the curve
(polynomial certificate, valid for every `a`, `d`). -/
theorem add_onCurve {x1 y1 x2 y2 x3 y3 : F} (h1 : OnCurve x1 y1) (h2 : OnCurve x2 y2)
    (hDp : 1 + d * x1 * x2 * y1 * y2 ≠ 0) (hDm : 1 - d * x1 * x2 * y1 * y2 ≠ 0)
    (hx3 : x3 * (1 + d * x1 * x2 * y1 * y2) = x1 * y2 + x2 * y1)
    (hy3 : y3 * (1 - d * x1 * x2 * y1 * y2) = y1 * y2 - a * x1 * x2) :
    OnCurve x3 y3 := by
  unfold OnCurve at *
  set Dp := 1 + d * x1 * x2 * y1 * y2 with hDp_def
  set Dm := 1 - d * x1 * x2 * y1 * y2 with hDm_def
  set Nx := x1 * y2 + x2 * y1 with hNx_def
  set Ny := y1 * y2 - a * x1 * x2 with hNy_def
  -- polynomial identity: a·Nx²·Dm² + Ny²·Dp² = Dp²·Dm² + d·Nx²·Ny²  (mod the curve equations)
  have key : a * Nx ^ 2 * Dm ^ 2 + Ny ^ 2 * Dp ^ 2 = Dp ^ 2 * Dm ^ 2 + d * Nx ^ 2 * Ny ^ 2 := by
    rw [hDp_def, hDm_def, hNx_def, hNy_def]
    linear_combination
      (-a^2*d*x1^2*x2^4*y2^2 - 2*a^2*x2^4*y2^2 + a^2*x2^4 + a*d^2*x1^2*x2^4*y2^4
        - a*d*x1^2*x2^2*y2^4 - a*d*x2^4*y1^2*y2^2 + 2*a*d*x2^4*y2^4 - 2*a*x2^2*y2^4
        + 4*a*x2^2*y2^2 + d^3*x1^2*x2^4*y1^2*y2^4 + d^2*x2^4*y1^2*y2^4 - d^2*x2^4*y2^4
        - d*x2^2*y1^2*y2^4 - 2*d*x2^2*y2^2 + y2^4) * h1
      + (a^2*d*x1^4*x2^2*y2^2 + 2*a^2*x1^2*x2^2*y2^2 - a^2*x1^2*x2^2 - 2*a*d*x1^2*x2^2*y2^2
        - a*x1^2*y2^2 + 2*a*x2^2*y1^2*y2^2 - a*x2^2*y1^2 - 2*a*x2^2*y2^2 + a*x2^2
        + d*x2^2*y1^4*y2^2 - 2*d*x2^2*y1^2*y2^2 + d*x2^2*y2^2 - y1^2*y2^2 + y2^2 + 1) * h2
  have hD : Dp ^ 2 * Dm ^ 2 ≠ 0 := by
    apply mul_ne_zero <;> apply pow_ne_zero <;> assumption
  apply mul_right_cancel₀ hD
  linear_combination key + a * (x3 * Dp + Nx) * Dm ^ 2 * hx3 + (y3 * Dm + Ny) * Dp ^ 2 * hy3
    - d * ((x3 * Dp + Nx) * (y3 * Dm) ^ 2 * hx3 + Nx ^ 2 * (y3 * Dm + Ny) * hy3)

/-- **L-EC, addition gadget.** The relations generated by `ark-r1cs-std 0.5.0`
`impl Add for AffineVar` (twisted_edwards/mod.rs:707-765), in constraint order
`A · B = C`:
```
u  : ((-a)·x1 + y1) · (x2 + y2) = u
v0 : y2 · x1 = v0
v1 : x2 · y1 = v1
t  : v0 · v1 = t                      (v2 = d·t)
x3 : x3 · (d·t + 1) = v0 + v1
y3 : y3 · (-(d·t - 1)) = u + a·v0 - v1
```
For on-curve inputs they force `1 ± d·t ≠ 0`, determine `x3, y3` uniquely as the Edwards
sum, and the output is on the curve. -/
theorem add_gadget {x1 y1 x2 y2 u v0 v1 t x3 y3 : F}
    (h1 : OnCurve x1 y1) (h2 : OnCurve x2 y2)
    (hu : ((-a) * x1 + y1) * (x2 + y2) = u)
    (hv0 : y2 * x1 = v0)
    (hv1 : x2 * y1 = v1)
    (ht : v0 * v1 = t)
    (hx3 : x3 * (d * t + 1) = v0 + v1)
    (hy3 : y3 * (-(d * t - 1)) = u + a * v0 - v1) :
    d * t + 1 ≠ 0 ∧ -(d * t - 1) ≠ 0 ∧
    x3 = (x1 * y2 + x2 * y1) / (1 + d * x1 * x2 * y1 * y2) ∧
    y3 = (y1 * y2 - a * x1 * x2) / (1 - d * x1 * x2 * y1 * y2) ∧
    OnCurve x3 y3 := by
  obtain ⟨hp, hm⟩ := add_denoms_ne_zero h1 h2
  have htv : t = (x1 * y2) * (x2 * y1) := by rw [← ht, ← hv0, ← hv1]; ring
  have hDp : 1 + d * x1 * x2 * y1 * y2 ≠ 0 := by
    intro h; apply hp; linear_combination h
  have hDm : 1 - d * x1 * x2 * y1 * y2 ≠ 0 := by
    intro h; apply hm; linear_combination h
  have hX : x3 * (1 + d * x1 * x2 * y1 * y2) = x1 * y2 + x2 * y1 := by
    rw [← hv0, ← hv1, htv] at hx3; linear_combination hx3
  have hY : y3 * (1 - d * x1 * x2 * y1 * y2) = y1 * y2 - a * x1 * x2 := by
    rw [← hu, ← hv0, ← hv1, htv] at hy3; linear_combination hy3
  refine ⟨?_, ?_, ?_, ?_, add_onCurve h1 h2 hDp hDm hX hY⟩
  · intro h; apply hp; rw [← h, htv]; ring
  · intro h; apply hm; rw [htv] at h; linear_combination h
  · exact eq_div_of_mul_eq hDp hX
  · exact eq_div_of_mul_eq hDm hY

/-- **L-EC, doubling gadget.** The relations generated by `ark-r1cs-std 0.5.0`
`AffineVar::double_in_place` (twisted_edwards/mod.rs:474-516), in constraint order:
```
xy : x · y = xy
x2 : x · x = x2
y2 : y · y = y2
x3 : x3 · (a·x2 + y2) = 2·xy
y3 : y3 · (-(a·x2 + y2) + 2) = y2 - a·x2
```
For an on-curve input both denominators are non-zero, `(x3, y3)` is uniquely the
Edwards sum `P + P`, and it is on the curve. -/
theorem dbl_gadget {x y xy x2 y2 x3 y3 : F} (h : OnCurve x y)
    (hxy : x * y = xy) (hx2 : x * x = x2) (hy2 : y * y = y2)
    (hx3 : x3 * (a * x2 + y2) = 2 * xy)
    (hy3 : y3 * (-(a * x2 + y2) + 2) = y2 - a * x2) :
    a * x2 + y2 ≠ 0 ∧ -(a * x2 + y2) + 2 ≠ 0 ∧
    x3 = (x * y + x * y) / (1 + d * x * x * y * y) ∧
    y3 = (y * y - a * x * x) / (1 - d * x * x * y * y) ∧
    OnCurve x3 y3 := by
  obtain ⟨hp, hm⟩ := add_denoms_ne_zero h h
  have hc := h
  unfold OnCurve at hc
  subst hxy hx2 hy2
  have hDp : 1 + d * x * x * y * y ≠ 0 := by
    intro h0; apply hp; linear_combination h0
  have hDm : 1 - d * x * x * y * y ≠ 0 := by
    intro h0; apply hm; linear_combination h0
  have hX : x3 * (1 + d * x * x * y * y) = x * y + x * y := by
    linear_combination hx3 - x3 * hc
  have hY : y3 * (1 - d * x * x * y * y) = y * y - a * x * x := by
    linear_combination hy3 + y3 * hc
  refine ⟨?_, ?_, eq_div_of_mul_eq hDp hX, eq_div_of_mul_eq hDm hY,
    add_onCurve h h hDp hDm (by linear_combination hX) (by linear_combination hY)⟩
  · intro h0; apply hDp; linear_combination h0 - hc
  · intro h0; apply hDm; linear_combination h0 + hc

/-- Negating the x-coordinate preserves the curve equation. -/
theorem onCurve_neg {x y : F} : OnCurve (-x) y ↔ OnCurve x y := by
  unfold OnCurve; constructor <;> intro h <;> linear_combination h

/-- `Boolean::select` / `FpVar::conditionally_select` (`cond·(t - f) = r - f`, `cond ∈ {0,1}`)
applied coordinate-wise with the same condition selects one of the two points; so the result is
on the curve if both candidates are. -/
theorem onCurve_select {c tx ty fx fy rx ry : F} (hc : c = 0 ∨ c = 1)
    (hx : c * (tx - fx) = rx - fx) (hy : c * (ty - fy) = ry - fy)
    (ht : OnCurve tx ty) (hf : OnCurve fx fy) : OnCurve rx ry := by
  rcases hc with rfl | rfl
  · have e1 : rx = fx := by linear_combination -hx
    have e2 : ry = fy := by linear_combination -hy
    rw [e1, e2]; exact hf
  · have e1 : rx = tx := by linear_combination -hx
    have e2 : ry = ty := by linear_combination -hy
    rw [e1, e2]; exact ht

end Picus
