import PicusLemmas.InField
import PicusLemmas.Edwards

/-!
Exports, as JSON, the objects the linkage script compares against the pinned `.r1cs` files:
* `toBitsLe 1 [(X, 1)]` — the exact constraint list of the Lean `to_bits_le` generator,
  with bit wires `1..254`, fresh wires from `255` (wire 0 is ONE), and the decomposed linear combination
  replaced by a placeholder wire `X = 1000000000` (coefficient 1);
* the curve constants `a`, `d` and the field modulus `p` used in the Lean statements.
-/

open Picus

def placeholder : ℕ := 1000000000

def lcJson (l : LC) : String :=
  "[" ++ ", ".intercalate (l.map fun t => s!"[{t.1}, \"{t.2.val}\"]") ++ "]"

def conJson (c : Con) : String := s!"[{lcJson c.A}, {lcJson c.B}, {lcJson c.C}]"

def exportJson : String :=
  let st := toBitsLe 1 [(placeholder, 1)]
  "{\"p\": \"" ++ toString p ++ "\",\n \"a\": \"" ++ toString a.val ++ "\",\n \"d\": \"" ++
    toString d.val ++ "\",\n \"placeholder\": " ++ toString placeholder ++
    ",\n \"to_bits_le\": {\"next\": " ++ toString st.next ++ ", \"cons\": [\n" ++
    ",\n".intercalate (st.cons.map conJson) ++ "]}}\n"

#eval IO.FS.writeFile "lean-export.json" exportJson
#eval IO.println s!"exported {(toBitsLe 1 [(placeholder, 1)]).cons.length} constraints"
