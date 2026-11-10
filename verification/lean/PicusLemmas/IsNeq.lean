import PicusLemmas.Field
import Mathlib.Tactic.LinearCombination

/-!
# L-neq: the `AllocatedFp::is_neq` gadget

`ark-r1cs-std 0.5.0` `fields/fp/mod.rs:368-438` allocates `ne` (no booleanity check) and a
multiplier `m`, and enforces, with `δ = self - other` (a linear combination):
```
(self - other) · m        = ne
(self - other) · (1 - ne) = 0        -- B is (!ne).lc() = ONE - ne
```
* `isNeq_ne`: `ne` is uniquely determined: `ne = 0` if `δ = 0`, else `ne = 1`.
* `isNeq_m_of_ne`: if `δ ≠ 0` the multiplier is unique, `m = δ⁻¹`.
* `isNeq_m_free`: if `δ = 0` every `m` satisfies both constraints (with `ne = 0`), so `m` is
  free exactly when the compared values are equal.
-/

namespace Picus

theorem isNeq_ne {δ m ne : F} (h1 : δ * m = ne) (h2 : δ * (1 - ne) = 0) :
    ne = if δ = 0 then 0 else 1 := by
  split_ifs with hδ
  · rw [← h1, hδ, zero_mul]
  · rcases mul_eq_zero.mp h2 with h | h
    · exact absurd h hδ
    · linear_combination -h

theorem isNeq_m_of_ne {δ m ne : F} (h1 : δ * m = ne) (h2 : δ * (1 - ne) = 0) (hδ : δ ≠ 0) :
    m = δ⁻¹ := by
  have hne := isNeq_ne h1 h2
  rw [if_neg hδ] at hne
  rw [hne] at h1
  exact eq_inv_of_mul_eq_one_right h1

theorem isNeq_m_free {δ : F} (hδ : δ = 0) (m : F) : δ * m = 0 ∧ δ * (1 - 0) = 0 := by
  subst hδ; simp

/-- **L-neq.** Any two solutions `(m, ne)`, `(m', ne')` of the `is_neq` constraints for the
same `δ` have the same output `ne`. -/
theorem isNeq_unique {δ m ne m' ne' : F}
    (h1 : δ * m = ne) (h2 : δ * (1 - ne) = 0) (h1' : δ * m' = ne') (h2' : δ * (1 - ne') = 0) :
    ne = ne' := by
  rw [isNeq_ne h1 h2, isNeq_ne h1' h2']

end Picus
