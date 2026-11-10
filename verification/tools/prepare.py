"""Build Picus inputs from the pinned r1cs + verified marks.

For each circuit writes:
  out/<id>.asis.r1cs        byte copy of the pin (header nPubOut=0, nPrvIn=all)
  out/<id>.free.r1cs        wire-permuted: inputs = public + prover-chosen free witnesses
  out/<id>.wiremap.json     new wire -> {old, section, free_label}
"""
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
from r1cs import parse, Marks, OUT, R1CS_DIR as SRC  # noqa: E402


def main():
    for cid in ('request', 'withdrawal', 'transition'):
        r = parse(f'{SRC}/{cid}.r1cs')
        mk = Marks(f'{OUT}/{cid}.marks.json')
        assert r.n_pubout == 0 and r.n_pubin == mk.num_instance - 1
        free = mk.free_wires()
        publics = list(range(1, mk.num_instance))
        free_ids = sorted(free)
        rest = [w for w in range(mk.num_instance, r.n_wires) if w not in free]
        order = [0] + publics + free_ids + rest
        shutil.copyfile(f'{SRC}/{cid}.r1cs', f'{OUT}/{cid}.asis.r1cs')
        r.write(f'{OUT}/{cid}.free.r1cs', order, 0, len(publics), len(free_ids))
        wiremap = [{'new': new, 'old': old, 'section': mk.wire_section(old), 'free': free.get(old)}
                   for new, old in enumerate(order)]
        json.dump(wiremap, open(f'{OUT}/{cid}.wiremap.json', 'w'))
        print(cid, 'wires', r.n_wires, 'publics', len(publics), 'free', len(free_ids),
              'targets', len(rest), 'constraints', len(r.constraints))
        labels = {}
        for w, l in free.items():
            labels[l] = labels.get(l, 0) + 1
        for l, n in labels.items():
            print('   free:', l, n)


if __name__ == '__main__':
    main()
