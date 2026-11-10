"""Decode a Picus UNSAFE counterexample log of a slice back to pinned-r1cs wires.
usage: cex.py <slice-dir> <slice-number> <log-file>"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from r1cs import Marks, OUT  # noqa: E402

d, n, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cid = d.rstrip('/').split('/')[-1].rsplit('-', 1)[0]
idx = json.load(open(f'{d}/index.json'))[n]
order = idx['order']
assume = json.load(open(f'{OUT}/assume-isneq.json')).get(cid, {})
wm = {}
sections = {}
blocks = {}
cur = None
for line in open(log, encoding='utf-8', errors='replace'):
    line = re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip()
    m = re.match(r'\s+(inputs|first possible outputs|second possible outputs|first internal variables|second internal variables):', line)
    if m:
        cur = m.group(1)
        blocks[cur] = {}
        continue
    m = re.match(r'\s+(?:main\.)?x?(\d+): (\S+)', line)
    if cur and m:
        blocks[cur][int(m.group(1))] = m.group(2)
mk = Marks(f'{OUT}/{cid}.marks.json')
a = blocks.get('first internal variables', {})
b = blocks.get('second internal variables', {})
a.update(blocks.get('first possible outputs', {}))
b.update(blocks.get('second possible outputs', {}))
diff = [k for k in a if a.get(k) != b.get(k)]
print(f'{cid} slice {n}: {len(diff)} differing wires')
for k in diff:
    old = order[k] if k < len(order) else None
    print(f'  local {k} -> pinned wire {old}: {a[k]} vs {b.get(k)} | {mk.wire_section(old) if old is not None else "aux"}'
          f'{" | known is_neq multiplier" if str(old) in assume else ""}')
