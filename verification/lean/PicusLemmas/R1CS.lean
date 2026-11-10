import PicusLemmas.Field

/-!
# A minimal R1CS model over `F`

A linear combination is a list of `(wire, coefficient)` pairs; wire `0` is the constant ONE
(as in the circom/iden3 `.r1cs` format and arkworks' `Variable::One`). A constraint
`⟨A, B, C⟩` is satisfied by an assignment `w` iff `⟦A⟧·⟦B⟧ = ⟦C⟧`.
-/

namespace Picus

/-- Linear combination `Σ cᵢ·w(iᵢ)` as a list of `(wire, coefficient)`. -/
abbrev LC := List (ℕ × F)

def LC.eval (w : ℕ → F) (l : LC) : F := (l.map fun t => t.2 * w t.1).sum

/-- An R1CS constraint `A · B = C`. -/
structure Con where
  A : LC
  B : LC
  C : LC

def Con.Sat (w : ℕ → F) (c : Con) : Prop := c.A.eval w * c.B.eval w = c.C.eval w

def LC.one : LC := [(0, 1)]
def LC.var (i : ℕ) : LC := [(i, 1)]
def LC.const (c : F) : LC := [(0, c)]
def LC.neg (l : LC) : LC := l.map fun t => (t.1, -t.2)

section
variable (w : ℕ → F)

@[simp] theorem LC.eval_nil : LC.eval w [] = 0 := rfl

@[simp] theorem LC.eval_cons (t : ℕ × F) (l : LC) :
    LC.eval w (t :: l) = t.2 * w t.1 + LC.eval w l := by
  simp [LC.eval]

@[simp] theorem LC.eval_append (l1 l2 : LC) :
    LC.eval w (l1 ++ l2) = LC.eval w l1 + LC.eval w l2 := by
  simp [LC.eval]

@[simp] theorem LC.eval_var (i : ℕ) : (LC.var i).eval w = w i := by
  simp [LC.var]

@[simp] theorem LC.eval_neg (l : LC) : (LC.neg l).eval w = -(l.eval w) := by
  induction l with
  | nil => simp [LC.neg]
  | cons t l ih =>
    simp only [LC.neg, List.map_cons, LC.eval_cons] at ih ⊢
    rw [ih]; ring

theorem LC.eval_one (h0 : w 0 = 1) : LC.one.eval w = 1 := by
  simp [LC.one, h0]

theorem LC.eval_const (h0 : w 0 = 1) (c : F) : (LC.const c).eval w = c := by
  simp [LC.const, h0]

theorem LC.eval_flatMap {α : Type} (f : α → LC) (l : List α) :
    LC.eval w (l.flatMap f) = (l.map fun x => (f x).eval w).sum := by
  induction l with
  | nil => simp
  | cons x l ih => simp [List.flatMap_cons, ih]

end

end Picus
