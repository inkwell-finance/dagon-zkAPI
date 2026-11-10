"""Compositional decomposition of a pinned r1cs into Picus-sized slices.

Every constraint is assigned to the slice that owns its highest-index wire
(arkworks creates a constraint only after allocating every wire it mentions).
Slices are contiguous witness-wire ranges [a, b), processed in order. Slice
inputs = every wire it mentions with index < a, plus prover-chosen free
witnesses (marks). Targets = the slice's own non-free wires.
If every slice is SAFE (all targets unique given its inputs), then by
induction on slice order every wire of the full circuit is a function of
(public inputs, free witnesses). Dropping constraints owned by later slices
only enlarges each slice's solution set, so SAFE stays sound.

Optional augmentation (--ec): for each twisted-Edwards add/double division
constraint t * D = N (exact arkworks 0.5 shapes for ark-ed-on-bn254, a=1,
d=168696/168700), append a fresh input wire `inv` and the constraint D * inv = 1.
This encodes D != 0, which holds for every on-curve input by the
completeness of the Edwards law (a square, d non-square in F_p); it is a
proof obligation recorded in the report, not something Picus checks.

usage: chunk.py <id> <slice_wires> [--ec] [--merge FILE]
writes out/slices/<id>/<n>.r1cs + index.json
"""
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from r1cs import parse, Marks, R1CS, P, OUT, R1CS_DIR  # noqa: E402

A_COEF = 1  # arkworks ed_on_bn254: a = 1, d = 168696/168700
def ec_pairs(clist):
    """Yield (kind, denominator LC) for every arkworks 0.5 twisted-Edwards
    add/double division pair in clist. Shapes (consecutive constraints):
      add   : x3 * (1 + k*w) = ..   ;  y3 * (1 - k*w) = ..   (k = d*const or d)
      double: x3 * (a*x2 + y2) = .. ;  y3 * (2 - a*x2 - y2) = ..
    Both denominators of each matched pair are returned."""
    def single(a):
        return len(a) == 1 and 0 not in a and next(iter(a.values())) == 1
    for i in range(len(clist) - 1):
        (a1, b1, _), (a2, b2, _) = clist[i], clist[i + 1]
        if not (single(a1) and single(a2)):
            continue
        k1 = set(b1) - {0}
        k2 = set(b2) - {0}
        if len(k1) == 1 and k1 == k2 and b1.get(0) == 1 and b2.get(0) == 1:
            (w,) = k1
            if (b1[w] + b2[w]) % P == 0 and next(iter(a1)) not in b1:
                yield (i, 'add', dict(b1))
                yield (i + 1, 'add', dict(b2))
                continue
        if 0 not in b1 and len(k1) == 2 and k1 == k2 and b2.get(0) == 2:
            if sorted(b1.values()) == [1, A_COEF] and all((b1[w] + b2[w]) % P == 0 for w in k1):
                yield (i, 'dbl', dict(b1))
                yield (i + 1, 'dbl', dict(b2))
    return None


GROUPS = {
    # withdrawal L705-L722: UInt bits allocated in one section and tied to the
    # public inputs only by later constraints. One slice per group, in order;
    # each constraint goes to the earliest group whose wires cover it.
    'withdrawal': {'groups': [
        ['withdrawal/L705 ', 'withdrawal/L706 ', 'withdrawal/L717 '],   # packed note fields
        ['withdrawal/L707-708 '],                                        # final_balance == public
        ['withdrawal/L710-711 '],                                        # conceded == public
        ['withdrawal/L709 ', 'withdrawal/L714 '],                        # balance = final + conceded
        ['withdrawal/L715 '],                                            # deposit >= balance
    ]},
}


def boolean_wires(constraints):
    """Wires w with a constraint equivalent to w*(w-1) = 0 -> {w: constraint index}."""
    out = {}
    for i, (a, b, c) in enumerate(constraints):
        if c:
            continue
        for x, y in ((a, b), (b, a)):
            if len(x) == 1 and 0 not in x and set(y) <= {0, *x}:
                (w, k), = x.items()
                if y.get(w) and (y.get(0, 0) * pow(y[w], -1, P)) % P == P - 1:
                    out[w] = i
    return out


def linear_form(con):
    """If con is linear (A or B constant-only/empty), return L with L = 0."""
    a, b, c = con
    def const(lc):
        return all(w == 0 for w in lc)
    if const(a) or const(b):
        k = (a.get(0, 0) if const(a) else b.get(0, 0))
        other = b if const(a) else a
        lin = defaultdict(int)
        for w, v in other.items():
            lin[w] = (lin[w] + k * v) % P
        for w, v in c.items():
            lin[w] = (lin[w] - v) % P
        return {w: v for w, v in lin.items() if v}
    return None


def normalise(clist, bools, targets, next_aux):
    """Equivalence-preserving rewrite into the shapes Picus' binary01/basis2
    lemmas match (shapes found by probing this Picus build):
      boolean : w * (w - 1) = 0
      bit sum : 0 = t - sum 2^i s_i   (A = B = empty), t a single wire
    A bit-sum whose remainder R is not a single wire gets a fresh auxiliary
    wire t defined by the linear constraint 0 = t + R/c (unique by the linear
    lemma). Returns (new clist, aux wires, stats)."""
    out, aux, stats = [], [], defaultdict(int)
    for con in clist:
        a, b, c = con
        # booleanity
        if not c and ((len(a) == 1 and next(iter(a)) in bools and set(b) <= {0, next(iter(a))})
                      or (len(b) == 1 and next(iter(b)) in bools and set(a) <= {0, next(iter(b))})):
            w = next(iter(a)) if len(a) == 1 and next(iter(a)) in bools and set(b) <= {0, next(iter(a))} else next(iter(b))
            out.append(({w: 1}, {0: P - 1, w: 1}, {}))
            stats['bool'] += 1
            continue
        lin = linear_form(con)
        if lin:
            cand = sorted(w for w in lin if w in bools and w in targets)
            runs, cur = [], []
            for w in cand:
                if cur and (w != cur[-1] + 1 or lin[w] != 2 * lin[cur[-1]] % P):
                    runs.append(cur)
                    cur = []
                cur.append(w)
            if cur:
                runs.append(cur)
            if len(runs) > 1:
                runs.append(cand)
            emitted = False
            for run in runs:
                s = {w: lin[w] for w in run}
                if not 1 < len(s) <= 253:
                    continue
                rest = {w: v for w, v in lin.items() if w not in s}
                for base in set(s.values()):
                    inv = pow(base, -1, P)
                    exps = {}
                    for w, v in s.items():
                        q = v * inv % P
                        if q & (q - 1) or q.bit_length() - 1 >= 253:
                            break
                        exps[w] = q.bit_length() - 1
                    else:
                        if sorted(exps.values()) == list(range(len(s))):
                            # L = base*sum 2^e s + R ; sum 2^e s = -R/base =: t
                            ninv = (-inv) % P
                            r_scaled = {w: v * ninv % P for w, v in rest.items()}
                            nz = {w: v for w, v in r_scaled.items() if v}
                            if len(nz) == 1 and 0 not in nz and next(iter(nz.values())) == 1:
                                t = next(iter(nz))
                            else:
                                t = next_aux + len(aux)
                                aux.append(t)
                                # 0 = t - (-R/base)  ->  C = {t: 1} + R/base
                                defn = {t: 1}
                                for w, v in r_scaled.items():
                                    defn[w] = (defn.get(w, 0) - v) % P
                                out.append(({}, {}, {w: v for w, v in defn.items() if v}))
                            cc = {t: 1}
                            for w, e in exps.items():
                                cc[w] = (P - (1 << e)) % P
                            out.append(({}, {}, cc))
                            stats['bitsum'] += 1
                            emitted = True
                            break
            if emitted:
                stats['bitsum_constraints'] += 1
        # the original constraint is always kept (rewrites are implied copies)
        out.append(con)
    return out, aux, stats


def build(cid, slice_wires, ec, tag, assume_file=None, ec_wires=48, implied=False):
    r = parse(f'{R1CS_DIR}/{cid}.r1cs')
    mk = Marks(f'{OUT}/{cid}.marks.json')
    free = dict(mk.free_wires())
    # lemma-backed inputs: the 254 canonical bits of every FpVar::to_bits_le
    lemma = {}
    for label, ws, we, _, _ in mk.section_ranges():
        if 'to_bits_le' in label:
            for w in range(ws, ws + 254):
                lemma[w] = 'L-bits: canonical 254-bit decomposition (' + label + ')'
    if assume_file:
        for w, why in json.load(open(assume_file)).get(cid, {}).items():
            lemma[int(w)] = why
    n0 = mk.num_instance
    bools = boolean_wires(r.constraints)
    ec_den = {i: (kind, den) for i, kind, den in ec_pairs(r.constraints)}
    owner_cons = defaultdict(list)
    for i, lcs in enumerate(r.constraints):
        top = max((w for lc in lcs for w in lc), default=0)
        owner_cons[top].append(i)
    secs = [(lab, s, e) for lab, s, e, _, _ in mk.section_ranges()]
    sec_of = {}
    for lab, s, e in secs:
        for w in range(s, e):
            sec_of[w] = lab
    groups_spec = GROUPS.get(cid, {})
    # 1. wire-range slices: section starts, EC sections split finer
    starts = sorted({s for _, s, _ in secs if s < r.n_wires} | {n0})
    grouped_range = None
    if groups_spec:
        g0 = min(s for lab, s, e in secs if any(lab.startswith(p) for g in groups_spec['groups'] for p in g))
        g1 = max(e for lab, s, e in secs if any(lab.startswith(p) for g in groups_spec['groups'] for p in g))
        grouped_range = (g0, g1)
        starts = [s for s in starts if not (g0 < s < g1)]
    if slice_wires == 0:
        starts = [n0]
    raw = []  # (own wire list, label)
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else r.n_wires
        if grouped_range and s == grouped_range[0]:
            raw.append(('group', s, e))
            continue
        lab = sec_of.get(s, '')
        is_ec = any(t in lab for t in ('*', 'R + PK', 'commitment + H', '(..) + J', 'R witness'))
        step = (e - s) if slice_wires == 0 else (ec_wires if is_ec else slice_wires)
        x = s
        while x < e:
            raw.append(('range', x, min(e, x + step)))
            x += step
    plan = []  # list of (own set, constraint list)
    for kind, a, b in raw:
        cons_range = sorted(i for w in range(a, b) for i in owner_cons.get(w, []))
        if kind == 'range':
            plan.append((list(range(a, b)), cons_range))
            continue
        # grouped: explicit target groups, constraints to the earliest covering group
        groups = []
        listed = set()
        for g in groups_spec['groups']:
            own = [w for w in range(a, b) if any(sec_of.get(w, '').startswith(p) for p in g)]
            listed.update(own)
            groups.append(own)
        rest = [w for w in range(a, b) if w not in listed]
        if rest:
            groups.append(rest)
        covered = set()
        assigned = set()
        for own in groups:
            covered |= set(own)
            mine = [i for i in cons_range if i not in assigned
                    and all(w == 0 or w < a or w >= b or w in covered or w in free or w in lemma
                            for lc in r.constraints[i] for w in lc)]
            assigned.update(mine)
            plan.append((own, mine))
        assert assigned == set(cons_range), 'grouped constraints not all assigned'
    d = f'{OUT}/slices/{cid}-{tag}'
    os.makedirs(d, exist_ok=True)
    for f in os.listdir(d):
        os.remove(os.path.join(d, f))
    index = []
    pre = [i for w in range(n0) for i in owner_cons.get(w, [])]
    tot = defaultdict(int)
    done = set(range(n0))
    all_cons = []
    for n, (own, cons) in enumerate(plan):
        if n == 0:
            cons = sorted(pre + cons)
        all_cons.extend(cons)
        own_set = set(own)
        used = set()
        for i in cons:
            for lc in r.constraints[i]:
                used.update(lc)
        used.discard(0)
        given = lambda w: w in done or w in free or w in lemma  # noqa: E731
        bad = [w for w in used if not given(w) and w not in own_set]
        assert not bad, f'slice {n} uses unproven later wires {bad[:5]}'
        targets = {w for w in used if not given(w)}
        unused_targets = [w for w in own if not given(w) and w not in used]
        clist = [r.constraints[i] for i in cons]
        aux_base = r.n_wires + 10
        clist, aux, stats = normalise(clist, bools, targets, aux_base)
        kinds = defaultdict(int)
        ins = sorted(w for w in used if given(w))
        if ec:
            extra = [(ec_den[i], r.constraints[i]) for i in cons if i in ec_den]
            base = aux_base + len(aux) + 10
            for k, ((kind, den), (ta, _tb, tc)) in enumerate(extra):
                kinds[kind] += 1
                inv = base + k
                clist.append((den, {inv: 1}, {0: 1}))          # D * inv = 1  (D != 0, EC lemma)
                if implied:
                    clist.append(({inv: 1}, dict(tc), dict(ta)))  # inv * N = t  (implied: t = t*D*inv = N*inv)
            ins += [base + k for k in range(len(extra))]
        order = [0] + ins + sorted(targets) + aux
        new_of = {old: new for new, old in enumerate(order)}
        sub = R1CS(len(order), 0, 0, len(ins),
                   [tuple({new_of[w]: c for w, c in lc.items()} for lc in con) for con in clist])
        sub.write(f'{d}/{n:04d}.r1cs', list(range(len(order))), 0, 0, len(ins))
        done |= own_set
        for k, v in stats.items():
            tot[k] += v
        tot['ec'] += sum(kinds.values())
        index.append({'slice': n, 'own': [min(own), max(own) + 1] if own else [], 'own_wires': own if len(own) < 2 or max(own) - min(own) + 1 != len(own) else None,
                      'constraints': len(cons),
                      'ec_aug': dict(kinds), 'norm': dict(stats), 'aux': len(aux),
                      'inputs': len(ins), 'targets': len(targets),
                      'lemma_inputs': sorted(w for w in used if w in lemma and w in own_set),
                      'unconstrained_targets': unused_targets,
                      'sections': sorted({sec_of.get(w, '?') for w in own}),
                      'order': order})
    assert sorted(all_cons) == list(range(len(r.constraints))), 'constraint partition broken'
    assert done >= set(range(r.n_wires)), 'wire coverage broken'
    json.dump(index, open(f'{d}/index.json', 'w'))
    print(cid, tag, 'slices', len(index), 'max constraints', max(x['constraints'] for x in index),
          dict(tot), 'unconstrained', sum(len(x['unconstrained_targets']) for x in index))
    return index


if __name__ == '__main__':
    cid, size, tag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ec = '--ec' in sys.argv
    assume = next((x.split('=', 1)[1] for x in sys.argv if x.startswith('--assume=')), None)
    ecw = next((int(x.split('=', 1)[1]) for x in sys.argv if x.startswith('--ec-wires=')), 48)
    build(cid, size, ec, tag, assume, ecw, '--implied' in sys.argv)
