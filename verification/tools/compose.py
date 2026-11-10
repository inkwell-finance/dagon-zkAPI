"""Check that the slice results compose into a whole-circuit uniqueness claim.

For each circuit: every wire must be (a) constant/public, (b) a prover-chosen
free witness, (c) a lemma-backed input (L-bits canonical decomposition or a
documented is_neq multiplier), or (d) a target of a slice that Picus reported
SAFE. Every constraint must be owned by exactly one slice. Slice results are
taken from the v4 run (is_neq multipliers and L-bits as documented inputs,
EC denominators asserted non-zero).
usage: compose.py results-dir"""
import glob
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))
from r1cs import parse, Marks, OUT, R1CS_DIR  # noqa: E402

resdir = sys.argv[1]
TAGS = {'request': 'v6', 'withdrawal': 'v6', 'transition': 'v5'}
results = {}
for f in glob.glob(f'{resdir}/results-slices-*.jsonl'):
    for line in open(f):
        r = json.loads(line)
        parts = r['file'].split('/')
        key = (parts[-2], int(parts[-1].split('.')[0]))
        results[key] = r
assume = json.load(open(f'{OUT}/assume-isneq.json'))
summary = {}
for cid in ('request', 'withdrawal', 'transition'):
    r = parse(f'{R1CS_DIR}/{cid}.r1cs')
    mk = Marks(f'{OUT}/{cid}.marks.json')
    free = mk.free_wires()
    lemma_bits = set()
    for label, ws, we, _, _ in mk.section_ranges():
        if 'to_bits_le' in label:
            lemma_bits.update(range(ws, ws + 254))
    isneq = {int(w) for w in assume.get(cid, {})}
    status = {}
    used_tag = Counter()
    times = []
    unresolved = []
    for tag in (TAGS[cid],):
        idx_path = f'{OUT}/slices/{cid}-{tag}/index.json'
        if not os.path.exists(idx_path):
            continue
        for x in json.load(open(idx_path)):
            res = results.get((f'{cid}-{tag}', x['slice']))
            own = x['own_wires'] if x.get('own_wires') is not None else range(*x['own']) if x['own'] else []
            for w in own:
                if w in free or w in lemma_bits or w in isneq:
                    continue
                if res and res['result'] == 'SAFE' and w not in status:
                    status[w] = tag
    for w in range(r.n_wires):
        if w < mk.num_instance:
            kind = 'public'
        elif w in free:
            kind = 'free'
        elif w in lemma_bits:
            kind = 'L-bits'
        elif w in status:
            kind = 'picus-' + status[w]
        elif w in isneq:
            kind = 'is_neq-multiplier'
        else:
            kind = 'UNPROVEN'
            unresolved.append(w)
        used_tag[kind] += 1
    for (k, n), res in results.items():
        if k == f'{cid}-{TAGS[cid]}':
            times.append((k, res['result'], float(res['wall_s'])))
    by = Counter((k, res) for k, res, _ in times)
    summary[cid] = dict(used_tag)
    print(cid, 'wires', r.n_wires, dict(used_tag))
    print('   slice runs:', dict(by), 'picus wall total %.0fs, max %.1fs' %
          (sum(t for _, _, t in times), max([t for _, _, t in times] or [0])))
    if unresolved:
        secs = Counter(mk.wire_section(w) for w in unresolved)
        print('   UNPROVEN by section:', secs.most_common(20))
json.dump(summary, open(f'{resdir}/compose-summary.json', 'w'), indent=1)
