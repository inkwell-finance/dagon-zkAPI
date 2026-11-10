"""Find arkworks AllocatedFp::is_neq multipliers: the exact two-constraint shape
    (x - y) * m = ne        (m occurs in no other constraint)
    (x - y) * (1 - ne) = 0
When x == y, m is unconstrained (benign: it feeds nothing). Writes
out/assume-isneq.json {cid: {wire: reason}} for chunk.py --assume."""
import json
import os
import sys
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(__file__))
from r1cs import parse, Marks, P, OUT, R1CS_DIR  # noqa: E402

res_all = {}
for cid in ('request', 'withdrawal', 'transition'):
    r = parse(f'{R1CS_DIR}/{cid}.r1cs')
    mk = Marks(f'{OUT}/{cid}.marks.json')
    occ = defaultdict(list)
    for i, (a, b, c) in enumerate(r.constraints):
        for w in set(a) | set(b) | set(c):
            if w:
                occ[w].append(i)
    res = {}
    for i, (a, b, c) in enumerate(r.constraints):
        for diff, m in ((a, b), (b, a)):
            if len(m) != 1 or 0 in m or next(iter(m.values())) != 1:
                continue
            w = next(iter(m))
            if len(occ[w]) != 1 or len(c) != 1 or 0 in c or next(iter(c.values())) != 1:
                continue
            ne = next(iter(c))
            want = {0: 1, ne: P - 1}
            partner = [j for j in occ[ne] if j != i and not r.constraints[j][2]
                       and ((r.constraints[j][0] == diff and r.constraints[j][1] == want)
                            or (r.constraints[j][1] == diff and r.constraints[j][0] == want))]
            if partner:
                res[str(w)] = ('is_neq multiplier m (constraints %d,%d: (x-y)*m = ne, (x-y)*(1-ne) = 0); '
                               'unconstrained only when x == y; occurs in no other constraint; section: %s'
                               % (i, partner[0], mk.wire_section(w)))
    res_all[cid] = res
    print(cid, len(res), Counter(v.split('section: ')[1] for v in res.values()).most_common())
json.dump(res_all, open(f'{OUT}/assume-isneq.json', 'w'), indent=1)
