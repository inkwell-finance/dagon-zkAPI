"""Negative controls: the linkage checks must reject a perturbed r1cs.

Each control perturbs one constraint of the pinned request.r1cs and checks that
link.py's corresponding check rejects it. Exit 0 only if every control is rejected.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import link  # noqa: E402

n, cons = link.parse(os.path.join(link.R1CS_DIR, 'request.r1cs'))
P = link.P
failed = []


def check(name, rejected, detail):
    print(f'{"REJECTED" if rejected else "NOT REJECTED"}  {name} -> {detail}')
    if not rejected:
        failed.append(name)


bits = link.link_bits('request', cons)
assert len(bits) == 2 and all(not s['mismatches'] for s in bits)
c = list(cons)
i = bits[0]['cons_range'][0] + 300
a, b, cc = c[i]
c[i] = (a, {**b, 0: 5}, cc)
mism = [len(s['mismatches']) for s in link.link_bits('request', c)]
check('L-bits: one in-field constraint perturbed', mism == [1, 0], f'mismatches per site {mism}')

add_i = next(i for i, kind, _ in link.ec_pairs(cons) if kind == 'add')
assert link.link_add(cons, add_i) is not None
c = list(cons)
a, b, cc = c[add_i]
b = dict(b)
den_wire = next(w for w in b if w)
b[den_wire] = (b[den_wire] + 1) % P
c[add_i] = (a, b, cc)
linked = link.link_add(c, add_i) is not None
check('L-EC: add denominator uses d+1', not linked, f'linked: {linked}')

c = list(cons)
a, b, cc = c[add_i + 1]
c[add_i + 1] = (a, b, {**cc, 0: (cc.get(0, 0) + 1) % P})
linked = link.link_add(c, add_i) is not None
check('L-EC: add y3 numerator perturbed', not linked, f'linked: {linked}')

from r1cs import Marks
marks = Marks(os.path.join(link.OUT, 'request.marks.json'))
for label in ('L339 R witness', 'L296 signing key Q witness'):
    start = next(cs for lab, _, _, cs, _ in marks.section_ranges() if label in lab)
    c = list(cons)
    a, b, cc = c[start + 2]
    c[start + 2] = (a, b, {**cc, 0: (cc.get(0, 0) + 1) % P})
    pairs, res, fails = link.link_ec(c)
    pv, pf = link.provenance(c, res)
    check(f'L-EC premise: on-curve check of {label} perturbed',
          len(pf) == 1, f'provenance failures {len(pf)}')

c = list(cons)
m = link.link_neq('request', cons)[0][0]['m']
c.append(({m: 1}, {0: 1}, {m: 1}))  # m now occurs in a second constraint
occ = sum(1 for (x, y, z) in c if m in x or m in y or m in z)
rows = [r['ok'] for r in link.link_neq('request', c)[0] if r['m'] == m]
check('L-neq: extra occurrence of m added', occ == 2 and rows == [False], f'occurrences {occ}, row ok {rows}')

print('NEGATIVE CONTROLS: all rejected' if not failed else f'NEGATIVE CONTROLS FAILED: {failed}')
sys.exit(1 if failed else 0)
