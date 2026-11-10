"""Link the Lean lemmas (verification/lean) to the pinned ceremony r1cs files.

For every constraint that the Picus result assumes a lemma about, check that it has exactly
the shape and coefficients of the hypotheses of the corresponding Lean theorem:

  L-bits  toBitsLe_canonical : the whole 640-constraint block of every FpVar::to_bits_le site
          equals, constraint by constraint (A, B, C as normalised wire->coeff maps), the list
          that the Lean generator `toBitsLe` produces (exported by Export.lean), after mapping
          Lean wires 1..484 -> base..base+483 and the placeholder X -> the decomposed LC x.
  L-EC    add_gadget / dbl_gadget : every add/double division pair Picus augmented with
          D*inv = 1 (chunk.py ec_pairs) is the arkworks 0.5 add/double gadget applied to
          identified input points: the gadget is re-generated here with arkworks' FpVar
          constant folding, and every generated constraint must equal the pinned one. Each of
          the Lean hypotheses (hu hv0 hv1 ht hx3 hy3 / hxy hx2 hy2 hx3 hy3) is then either a
          pinned constraint verbatim, or an identity of linear combinations (constant folding).
  L-neq   isNeq_* : every one of the 74 helper wires m sits in exactly the pair
          (d)*(m) = (ne), (d)*(1 - ne) = 0 with the same LC d, and occurs in no other
          constraint of the whole r1cs.

usage: python link.py  (writes $VERIF_WORK/out/link-results.json and prints a summary)
"""
import hashlib
import json
import os
import struct
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = {
    'request': 'ed73c7919790d3cb75e9fc60373aa7ac3c5fb4820c43f2364451ebfdb7f14566',
    'withdrawal': 'a2b46576733aafbe90b816a26cfe8f40c613d76581fbf9e982026e191fa0c973',
    'transition': 'a9cd49c195bd2d6e80664672f0994542baa12aa661e8e93bd9563f3bed8ad1c1',
}
sys.path.insert(0, os.path.join(HERE, '..', '..', 'tools'))
from r1cs import R1CS_DIR, OUT  # noqa: E402
from chunk import ec_pairs  # noqa: E402  (the exact matcher used to build the Picus slices)
EXPORT = os.path.join(OUT, 'lean-export.json')
ASSUME = os.path.join(OUT, 'assume-isneq.json')

LEAN = json.load(open(EXPORT))
P = int(LEAN['p'])
A_COEF = int(LEAN['a'])
D_COEF = int(LEAN['d'])
PH = LEAN['placeholder']


# ---------------------------------------------------------------- r1cs parsing
def parse(path):
    data = open(path, 'rb').read()
    assert data[:4] == b'r1cs'
    _, nsec = struct.unpack_from('<II', data, 4)
    pos, sections = 12, {}
    for _ in range(nsec):
        kind, size = struct.unpack_from('<IQ', data, pos)
        pos += 12
        sections[kind] = (pos, size)
        pos += size
    hp, _ = sections[1]
    fs = struct.unpack_from('<I', data, hp)[0]
    assert int.from_bytes(data[hp + 4:hp + 4 + fs], 'little') == P, 'field mismatch'
    q = hp + 4 + fs
    n_wires = struct.unpack_from('<I', data, q)[0]
    m = struct.unpack_from('<I', data, q + 24)[0]
    cp, _ = sections[2]
    cons = []
    for _ in range(m):
        lcs = []
        for _ in range(3):
            n = struct.unpack_from('<I', data, cp)[0]
            cp += 4
            lc = {}
            for _ in range(n):
                w = struct.unpack_from('<I', data, cp)[0]
                lc[w] = (lc.get(w, 0) + int.from_bytes(data[cp + 4:cp + 36], 'little')) % P
                cp += 36
            lcs.append(norm(lc))
        cons.append(tuple(lcs))
    return n_wires, cons


def norm(lc):
    return {w: c % P for w, c in lc.items() if c % P}


def lc_add(*lcs):
    out = defaultdict(int)
    for lc in lcs:
        for w, c in lc.items():
            out[w] += c
    return norm(out)


def lc_scale(k, lc):
    return norm({w: k * c for w, c in lc.items()})


def inv(x):
    return pow(x, P - 2, P)


# ---------------------------------------------------------------- L-bits
def lean_bits_block():
    cons = []
    for a, b, c in LEAN['to_bits_le']['cons']:
        cons.append(tuple(norm({w: int(k) % P for w, k in
                                Counter_sum(lc)}) for lc in (a, b, c)))
    return cons


def Counter_sum(lc):
    acc = defaultdict(int)
    for w, k in lc:
        acc[w] += int(k)
    return acc.items()


def link_bits(cid, cons):
    lean = lean_bits_block()
    n_lean_wires = LEAN['to_bits_le']['next'] - 1  # Lean wires 1..next-1
    pow2 = [pow(2, i, P) for i in range(254)]
    sites = []
    # independent detection: packing constraint 0*0 = sum 2^i b_i - x over 254 consecutive wires
    for idx, (a, b, c) in enumerate(cons):
        if a or b or len(c) < 255:
            continue
        for base in sorted(c):
            if all(c.get(base + i) == pow2[i] for i in range(254)):
                sites.append((idx - 254, base))
                break
    out = []
    for start, base in sites:
        packing = cons[start + 254][2]
        x = lc_add({base + i: pow2[i] for i in range(254)}, lc_scale(P - 1, packing))  # x = sum - C

        def m(lc):
            r = defaultdict(int)
            for w, k in lc.items():
                if w == PH:
                    for xw, xk in x.items():
                        r[xw] += k * xk
                elif w == 0:
                    r[0] += k
                else:
                    assert 1 <= w <= n_lean_wires
                    r[base + w - 1] += k
            return norm(r)
        mism = [j for j, (a, b, c) in enumerate(lean)
                if start + j >= len(cons) or (m(a), m(b), m(c)) != cons[start + j]]
        out.append({'cons_range': [start, start + len(lean)], 'bit_wires': [base, base + 254],
                    'fresh_wires': [base + 254, base + n_lean_wires],
                    'x_lc_wires': sorted(x), 'x_before_bits': max(x) < base,
                    'constraints_compared': len(lean), 'mismatches': mism})
    return out


# ---------------------------------------------------------------- L-EC
class V:
    """arkworks FpVar: constant (lc has only wire 0, const=True) or variable LC."""
    def __init__(self, lc, const=False):
        self.lc = norm(lc)
        self.const = const

    @staticmethod
    def c(k):
        return V({0: k % P}, True)

    def val(self):
        assert self.const
        return self.lc.get(0, 0)

    def __add__(self, o):
        return V(lc_add(self.lc, o.lc), self.const and o.const)

    def __neg__(self):
        return V(lc_scale(P - 1, self.lc), self.const)

    def __sub__(self, o):
        return self + (-o)


class Gen:
    """Re-generates arkworks constraints with FpVar constant folding and records, for each
    Lean hypothesis, whether it is an emitted constraint or a folded LC identity."""
    def __init__(self, nxt):
        self.nxt = nxt
        self.cons = []
        self.hyp = {}

    def alloc(self):
        w = self.nxt
        self.nxt += 1
        return V({w: 1})

    def mul(self, x, y, name=None):
        if x.const and y.const:
            r = V.c(x.val() * y.val())
            kind = 'const'
        elif x.const or y.const:
            k, v = (x.val(), y) if x.const else (y.val(), x)
            r = V(lc_scale(k, v.lc))
            kind = 'folded'
        else:
            r = self.alloc()
            self.cons.append((x.lc, y.lc, r.lc))
            kind = 'constraint'
        if name:
            self.hyp[name] = kind
        return r

    def mul_equals(self, x, y, z, name):
        assert not x.const
        if y.const:
            raise ValueError('constant denominator: not an add/double instance')
        self.cons.append((x.lc, y.lc, z.lc))
        self.hyp[name] = 'constraint'


def te_add(p1, p2, nxt):
    """twisted_edwards/mod.rs:707-765 (impl Add for AffineVar), a = COEFF_A, d = COEFF_D."""
    (x1, y1), (x2, y2) = p1, p2
    g = Gen(nxt)
    u1 = g.mul(x1, V.c(-A_COEF)) + y1
    u2 = x2 + y2
    u = g.mul(u1, u2, 'hu')
    v0 = g.mul(y2, x1, 'hv0')
    v1 = g.mul(x2, y1, 'hv1')
    t = g.mul(v0, v1, 'ht')
    v2 = g.mul(t, V.c(D_COEF))
    x3 = g.alloc()
    g.mul_equals(x3, v2 + V.c(1), v0 + v1, 'hx3')
    y3 = g.alloc()
    one_minus_v2 = -(v2 - V.c(1))
    a_v0 = g.mul(v0, V.c(A_COEF))
    g.mul_equals(y3, one_minus_v2, u + a_v0 - v1, 'hy3')
    return g


def te_double(pt, nxt):
    """twisted_edwards/mod.rs:474-516 (double_in_place)."""
    x, y = pt
    g = Gen(nxt)
    xy = g.mul(x, y, 'hxy')
    x2 = g.mul(x, x, 'hx2')
    y2 = g.mul(y, y, 'hy2')
    a_x2 = g.mul(x2, V.c(A_COEF))
    x3 = g.alloc()
    g.mul_equals(x3, a_x2 + y2, xy + xy, 'hx3')
    y3 = g.alloc()
    g.mul_equals(y3, -(a_x2 + y2) + V.c(2), y2 - a_x2, 'hy3')
    return g


def sqrt_mod(a):
    a %= P
    if a == 0:
        return [0]
    if pow(a, (P - 1) // 2, P) != 1:
        return []
    # Tonelli-Shanks
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 5  # 5 is a non-residue (it generates F_p^*, see the Lean Pratt certificate)
    mm, c, t, r = s, pow(z, q, P), pow(a, q, P), pow(a, (q + 1) // 2, P)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (mm - i - 1), P)
        mm, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    return sorted({r, P - r})


def solve_quad(qa, qb, qc):
    """roots of qa*z^2 + qb*z + qc = 0 over F_p"""
    if qa == 0:
        return [] if qb == 0 else [(-qc) * inv(qb) % P]
    disc = (qb * qb - 4 * qa * qc) % P
    return sorted({(-qb + s) * inv(2 * qa) % P for s in sqrt_mod(disc)})


def on_curve(x, y):
    return (A_COEF * x * x + y * y - 1 - D_COEF * x * x % P * y * y) % P == 0


def const_point_candidates(alpha, beta, ny, var_first):
    """One operand is a constant point (cx, cy), the other a variable point (X, Y).
    var_first (self var, other const): alpha = A_t = cy*X1, beta = B_t = cx*Y1,
        N_y = cy*Y1 - cx*X1  = r*beta - alpha/r          (r = cy/cx)
    const_first (self const, other var): alpha = cx*Y2, beta = cy*X2,
        N_y = cy*Y2 - cx*X2  = r*alpha - beta/r          (r = cy/cx)
    Returns candidate (const point, var point) pairs; the caller re-generates and compares."""
    lin, other = (beta, alpha) if var_first else (alpha, beta)
    keys = set(alpha) | set(beta) | set(ny)
    rs = None
    for k in keys:  # lin[k]*r^2 - ny[k]*r - other[k] = 0
        cand = set(solve_quad(lin.get(k, 0), -ny.get(k, 0) % P, -other.get(k, 0) % P))
        if lin.get(k, 0) == 0 and ny.get(k, 0) == 0:
            continue
        rs = cand if rs is None else rs & cand
    out = []
    for r in sorted(rs or []):
        if r == 0:
            continue
        # cx^2 (1 + a r^2) ... curve: a cx^2 + cy^2 = 1 + d cx^2 cy^2, cy = r cx; s = cx^2
        for s in solve_quad(D_COEF * r * r % P, -(A_COEF + r * r) % P, 1):
            for cx in sqrt_mod(s):
                cy = r * cx % P
                if cx == 0 or cy == 0:
                    continue
                if var_first:
                    X, Y = lc_scale(inv(cy), alpha), lc_scale(inv(cx), beta)
                else:
                    Y, X = lc_scale(inv(cx), alpha), lc_scale(inv(cy), beta)
                out.append(((V.c(cx), V.c(cy)), (V(X), V(Y))))
    # among the sign choices (cx, cy) <-> (-cx, -cy), prefer the variable point with +1 coefficients
    out.sort(key=lambda cv: -sum(k == 1 for lc in (cv[1][0].lc, cv[1][1].lc) for k in lc.values()))
    deg = []
    # degenerate constant points with a zero coordinate: (0, +-1), (+-1, 0)
    for cx, cy in ((0, 1), (0, P - 1), (1, 0), (P - 1, 0)):
        try:
            if var_first:  # alpha = cy*X1, beta = cx*Y1, N_y = cy*Y1 - cx*X1
                if cy and cx == 0:
                    X, Y = lc_scale(inv(cy), alpha), lc_scale(inv(cy), ny)
                elif cx and cy == 0:
                    Y, X = lc_scale(inv(cx), beta), lc_scale(P - inv(cx), ny)
                else:
                    continue
            else:          # alpha = cx*Y2, beta = cy*X2, N_y = cy*Y2 - cx*X2
                if cy and cx == 0:
                    X, Y = lc_scale(inv(cy), beta), lc_scale(inv(cy), ny)
                elif cx and cy == 0:
                    Y, X = lc_scale(inv(cx), alpha), lc_scale(P - inv(cx), ny)
                else:
                    continue
            deg.append(((V.c(cx), V.c(cy)), (V(X), V(Y))))
        except ZeroDivisionError:
            pass
    return out, deg


def match(g, cons, start):
    return all(start + j < len(cons) and g.cons[j] == cons[start + j] for j in range(len(g.cons)))


def first_new_wire(lcs):
    return min(w for lc in lcs for w in lc if w)


def link_add(cons, i):
    """i = index of the x3 constraint. Try var+var, then var+const, then const+var."""
    x3w = next(iter(cons[i][0]))
    tries = []
    # var + var: u, v0, v1, t, x3, y3
    if i >= 4:
        (_, _, _), (ya, xb, _), (xa, yb, _) = cons[i - 4], cons[i - 3], cons[i - 2]
        tries.append(('var+var', (V(xb), V(yb)), (V(xa), V(ya)), 4))
    # one constant operand: t, x3, y3 (non-degenerate constants first, then (0,+-1), (+-1,0))
    alpha, beta, _ = cons[i - 1]
    ny = cons[i + 1][2]
    vc, vc_deg = const_point_candidates(alpha, beta, ny, True)
    cv, cv_deg = const_point_candidates(alpha, beta, ny, False)
    tries += [('var+const', vpt, cpt, 1) for cpt, vpt in vc]
    tries += [('const+var', cpt, vpt, 1) for cpt, vpt in cv]
    tries += [('const+var', cpt, vpt, 1) for cpt, vpt in cv_deg]
    tries += [('var+const', vpt, cpt, 1) for cpt, vpt in vc_deg]
    for kind, p1, p2, back in tries:
        if True:
            start = i - back
            if start < 0 or not any(w for w in cons[start][2]):
                continue
            first = first_new_wire([cons[start][2]])
            try:
                g = te_add(p1, p2, first)
            except ValueError:
                continue
            if len(g.cons) == back + 2 and match(g, cons, start) and x3w == g.nxt - 2:
                consts = [pt for pt in (p1, p2) if pt[0].const and pt[1].const]
                if any(not on_curve(pt[0].val(), pt[1].val()) for pt in consts):
                    continue
                return {'kind': kind, 'cons': [start, start + len(g.cons)], 'hyp': g.hyp,
                        'p1': [p1[0].lc, p1[1].lc], 'p2': [p2[0].lc, p2[1].lc]}
    return None


def link_dbl(cons, i):
    a, b, _ = cons[i - 3]
    g = te_double((V(a), V(b)), first_new_wire([cons[i - 3][2]]))
    if len(g.cons) == 5 and match(g, cons, i - 3):
        return {'kind': 'double', 'cons': [i - 3, i + 2], 'hyp': g.hyp, 'p': [a, b]}
    return None


def link_ec(cons):
    pairs = [(i, k) for i, k, _ in ec_pairs(cons)]
    firsts = [(i, k) for n, (i, k) in enumerate(pairs) if n % 2 == 0]
    assert all(pairs[2 * n + 1][0] == i + 1 for n, (i, _) in enumerate(firsts))
    res, fails = [], []
    for i, k in firsts:
        r = link_add(cons, i) if k == 'add' else link_dbl(cons, i)
        (res if r else fails).append(r or i)
    return pairs, res, fails


# ---------------------------------------------------------------- L-EC premise: on-curve inputs
def key(pt):
    return tuple(tuple(sorted(lc.items())) for lc in pt)


class Provenance:
    """Establishes, by structural induction over the r1cs, that every add/double input point is
    on the curve in every satisfying assignment. Rules (each backed by a Lean lemma or a direct
    finite check):
      const    both coordinates constant and on the curve (checked here)
      alloc    P = (x, y) wires with the arkworks on-curve check x*x=x2, y*y=y2,
               (d*x2 - 1)*y2 = a*x2 - 1                           (Lean onCurve_of_gadget)
      output   P = (x3, y3) of an earlier linked add/double gadget  (Lean add_gadget/dbl_gadget)
      neg      P = (-X, Y) with (X, Y) established                  (Lean onCurve_neg)
      boolsel  coordinates are affine in <= 4 boolean wires; every 0/1 assignment gives an
               on-curve constant (checked here by enumeration)
      select   x, y defined by Boolean::select constraints cond*(t - f) = r - f with the same
               boolean cond, and (tx, ty), (fx, fy) established       (Lean onCurve_select)
    """
    def __init__(self, cons):
        self.cons = cons
        self.boolean = set()
        self.square = defaultdict(set)
        self.curve = set()
        self.by_c = defaultdict(list)
        for idx, (a, b, c) in enumerate(cons):
            if not c and len(b) == 1 and 0 not in b and b == {next(iter(b)): 1}:
                w = next(iter(b))
                if a == {0: 1, w: P - 1}:
                    self.boolean.add(w)
            if len(a) == 1 and a == b and 0 not in a and a[next(iter(a))] == 1 and len(c) == 1 \
                    and 0 not in c and c[next(iter(c))] == 1:
                self.square[next(iter(a))].add(next(iter(c)))
            if len(b) == 1 and 0 not in b and b[next(iter(b))] == 1:
                y2 = next(iter(b))
                x2s = [w for w in a if w]
                if len(x2s) == 1:
                    x2 = x2s[0]
                    if a == {x2: D_COEF, 0: P - 1} and c == {x2: A_COEF % P, 0: P - 1}:
                        self.curve.add((x2, y2))
            for w, k in c.items():
                if w and k == 1:
                    self.by_c[w].append(idx)
        self.outputs = {}
        self.memo = {}
        self.rules = Counter()

    def is_bool_lc(self, lc):
        ws = [w for w in lc if w]
        if len(ws) != 1 or ws[0] not in self.boolean:
            return None
        b = ws[0]
        if lc == {b: 1}:
            return b
        if lc == {0: 1, b: P - 1}:
            return b
        return None

    def established(self, pt, depth=0):
        k = key(pt)
        if k in self.memo:
            return self.memo[k]
        self.memo[k] = None  # cycle guard
        r = self._est(pt, depth)
        self.memo[k] = r
        if r:
            self.rules[r] += 1
        return r

    def _est(self, pt, depth):
        x, y = pt
        wires = sorted({w for lc in pt for w in lc if w})
        if not wires:
            return 'const' if on_curve(x.get(0, 0), y.get(0, 0)) else None
        if key(pt) in self.outputs:
            return 'output'
        if len(x) == 1 and len(y) == 1 and 0 not in x and 0 not in y:
            (xw, xk), (yw, yk) = next(iter(x.items())), next(iter(y.items()))
            if xk == 1 and yk == 1 and any((x2, y2) in self.curve for x2 in self.square[xw]
                                           for y2 in self.square[yw]):
                return 'alloc'
            if xk == P - 1 and yk == 1 and self.established(({xw: 1}, y), depth + 1):
                return 'neg'
        if len(wires) <= 4 and all(w in self.boolean for w in wires):
            for bits in range(1 << len(wires)):
                env = {w: (bits >> j) & 1 for j, w in enumerate(wires)}
                ev = [sum(k * (1 if w == 0 else env[w]) for w, k in lc.items()) % P for lc in pt]
                if not on_curve(*ev):
                    return None
            return 'boolsel'
        if depth < 64 and len(x) == 1 and len(y) == 1 and 0 not in x and 0 not in y \
                and x[next(iter(x))] == 1 and y[next(iter(y))] == 1:
            rx, ry = next(iter(x)), next(iter(y))
            for ix in self.by_c[rx]:
                for iy in self.by_c[ry]:
                    ax, bx, cx = self.cons[ix]
                    ay, by_, cy = self.cons[iy]
                    if ax != ay or self.is_bool_lc(ax) is None:
                        continue
                    fx = lc_add({rx: 1}, lc_scale(P - 1, cx))
                    fy = lc_add({ry: 1}, lc_scale(P - 1, cy))
                    tx, ty = lc_add(bx, fx), lc_add(by_, fy)
                    if rx in fx or rx in tx or ry in fy or ry in ty:
                        continue
                    if self.established((tx, ty), depth + 1) and self.established((fx, fy), depth + 1):
                        return 'select'
        return None


def provenance(cons, linked):
    pv = Provenance(cons)
    fails = []
    for r in sorted(linked, key=lambda r: r['cons'][0]):
        ins = [r['p']] if r['kind'] == 'double' else [r['p1'], r['p2']]
        for pt in ins:
            if not pv.established(tuple(norm(lc) for lc in pt)):
                fails.append((r['cons'], pt))
        x3 = r['cons'][1] - 2
        x3w = next(iter(cons[x3][0]))
        y3w = next(iter(cons[x3 + 1][0]))
        pv.outputs[key(({x3w: 1}, {y3w: 1}))] = r['cons']
    return pv, fails


# ---------------------------------------------------------------- L-neq
def link_neq(cid, cons):
    occ = defaultdict(list)
    for idx, (a, b, c) in enumerate(cons):
        for w in set(a) | set(b) | set(c):
            if w:
                occ[w].append(idx)
    assume = json.load(open(ASSUME)).get(cid, {})
    rows = []
    for ms in sorted(assume, key=int):
        m = int(ms)
        rec = {'m': m, 'occurrences': occ[m]}
        ok = len(occ[m]) == 1
        if ok:
            i = occ[m][0]
            d, bm, cne = cons[i]
            ok = bm == {m: 1} and len(cne) == 1 and 0 not in cne and next(iter(cne.values())) == 1
            if ok:
                ne = next(iter(cne))
                partner = [j for j in occ[ne] if j != i and cons[j] == (d, {0: 1, ne: P - 1}, {})]
                ok = len(partner) == 1 and m not in d and ne not in d
                rec.update({'ne': ne, 'cons': [i] + partner, 'delta_wires': sorted(d)})
        rec['ok'] = ok
        rows.append(rec)
    # independent re-detection of the shape over the whole file
    found = set()
    for idx, (a, b, c) in enumerate(cons):
        if len(b) == 1 and 0 not in b and next(iter(b.values())) == 1 and len(c) == 1 and 0 not in c \
                and next(iter(c.values())) == 1:
            mw, ne = next(iter(b)), next(iter(c))
            if len(occ[mw]) == 1 and any(cons[j] == (a, {0: 1, ne: P - 1}, {}) for j in occ[ne] if j != idx):
                found.add(mw)
    return rows, found


def main():
    report = {'lean_export': {'p': str(P), 'a': A_COEF, 'd': str(D_COEF)}, 'circuits': {}}
    for cid in ('request', 'withdrawal', 'transition'):
        path = f'{R1CS_DIR}/{cid}.r1cs'
        sha = hashlib.sha256(open(path, 'rb').read()).hexdigest()
        assert sha == PINS[cid], f'{cid}: pin mismatch {sha}'
        n_wires, cons = parse(path)
        bits = link_bits(cid, cons)
        # the bit wires Picus took as L-bits inputs (chunk.py: 254 wires from each to_bits_le section)
        from r1cs import Marks
        mk = Marks(f'{OUT}/{cid}.marks.json')
        picus_bits = {w for lab, ws, *_ in mk.section_ranges() if 'to_bits_le' in lab for w in range(ws, ws + 254)}
        linked_bits = {w for s_ in bits for w in range(*s_['bit_wires'])}
        pairs, ec, ec_fail = link_ec(cons)
        neq, neq_found = link_neq(cid, cons)
        pv, prov_fail = provenance(cons, ec)
        kinds = Counter(r['kind'] for r in ec)
        hyp = Counter((r['kind'], h, v) for r in ec for h, v in r['hyp'].items())
        report['circuits'][cid] = {
            'sha256': sha, 'wires': n_wires, 'constraints': len(cons),
            'bits_sites': bits, 'bits_equal_picus_lemma_wires': picus_bits == linked_bits,
            'bits_wires': len(linked_bits),
            'ec_pairs': len(pairs) // 2, 'ec_denominator_constraints': len(pairs),
            'ec_linked': len(ec), 'ec_failed': ec_fail, 'ec_kinds': dict(kinds),
            'ec_hypothesis_forms': {f'{k}/{h}': {} for k, h, _ in hyp},
            'ec_inputs_checked': sum(1 if r['kind'] == 'double' else 2 for r in ec),
            'ec_input_provenance_rules': dict(pv.rules), 'ec_input_provenance_failures': prov_fail,
            'neq_wires': len(neq), 'neq_ok': sum(r['ok'] for r in neq),
            'neq_redetected': len(neq_found), 'neq_sets_equal': neq_found == {r['m'] for r in neq},
            'neq_rows': neq,
        }
        for (k, h, v), n in hyp.items():
            report['circuits'][cid]['ec_hypothesis_forms'][f'{k}/{h}'][v] = n
        c = report['circuits'][cid]
        print(f'== {cid}: sha256 {sha} (pin OK), {n_wires} wires, {len(cons)} constraints')
        for s in bits:
            print(f"  L-bits site cons {s['cons_range']} bits {s['bit_wires']}: "
                  f"{s['constraints_compared']} constraints compared with Lean toBitsLe, "
                  f"mismatches {len(s['mismatches'])}; x = LC over {len(s['x_lc_wires'])} wires, all < base: {s['x_before_bits']}")
        print(f"  L-bits: {len(linked_bits)} bit wires linked; equal to the Picus L-bits input set: {c['bits_equal_picus_lemma_wires']}")
        print(f"  L-EC: {c['ec_pairs']} division pairs ({c['ec_denominator_constraints']} denominator constraints), "
              f"linked {c['ec_linked']}, failed {len(ec_fail)}; kinds {dict(kinds)}")
        for kh, forms in sorted(c['ec_hypothesis_forms'].items()):
            print(f'    {kh}: {forms}')
        print(f"  L-EC premise (inputs on curve): {c['ec_inputs_checked']} input points checked, "
              f"failures {len(prov_fail)}; distinct points by rule {dict(pv.rules)}")
        print(f"  L-neq: {c['neq_wires']} helper wires, shape+single-occurrence OK {c['neq_ok']}, "
              f"independently re-detected {c['neq_redetected']}, sets equal {c['neq_sets_equal']}")
        for r in neq:
            print(f"    m={r['m']} ne={r.get('ne')} cons={r.get('cons')} occurrences={len(r['occurrences'])} ok={r['ok']}")
    json.dump(report, open(os.path.join(OUT, 'link-results.json'), 'w'), indent=1, default=str)
    ok = all(not s['mismatches'] for c in report['circuits'].values() for s in c['bits_sites']) and \
        all(c['bits_equal_picus_lemma_wires'] for c in report['circuits'].values()) and \
        all(not c['ec_failed'] and not c['ec_input_provenance_failures'] and
            c['neq_ok'] == c['neq_wires'] and c['neq_sets_equal']
            for c in report['circuits'].values())
    print('ALL LINKED' if ok else 'LINKAGE FAILURES')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
