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


c = list(cons)
a, b, cc = c[18482 + 300]
c[18482 + 300] = (a, {**b, 0: 5}, cc)
mism = [len(s['mismatches']) for s in link.link_bits('request', c)]
check('L-bits: one in-field constraint perturbed', mism == [1, 0], f'mismatches per site {mism}')

c = list(cons)
a, b, cc = c[21011]
b = dict(b)
b[20891] = (b[20891] + 1) % P
c[21011] = (a, b, cc)
linked = link.link_add(c, 21011) is not None
check('L-EC: add denominator uses d+1', not linked, f'linked: {linked}')

c = list(cons)
a, b, cc = c[21012]
c[21012] = (a, b, {**cc, 20888: 2})
linked = link.link_add(c, 21011) is not None
check('L-EC: add y3 numerator perturbed', not linked, f'linked: {linked}')

c = list(cons)
a, b, cc = c[23252]
c[23252] = (a, b, {**cc, 0: 5})
pairs, res, fails = link.link_ec(c)
pv, pf = link.provenance(c, res)
check('L-EC premise: on-curve check of the R witness perturbed', len(pf) == 1, f'provenance failures {len(pf)}')

c = list(cons)
m = 18962  # an is_neq multiplier (request)
c.append(({m: 1}, {0: 1}, {m: 1}))  # m now occurs in a second constraint
occ = sum(1 for (x, y, z) in c if m in x or m in y or m in z)
rows = [r['ok'] for r in link.link_neq('request', c)[0] if r['m'] == m]
check('L-neq: extra occurrence of m added', occ == 2 and rows == [False], f'occurrences {occ}, row ok {rows}')

print('NEGATIVE CONTROLS: all rejected' if not failed else f'NEGATIVE CONTROLS FAILED: {failed}')
sys.exit(1 if failed else 0)
