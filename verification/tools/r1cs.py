"""r1cs utilities for the circuit verification (iden3 binary r1cs v1).

parse(path)             -> R1CS
R1CS.write(path, ...)   -> relabelled copy with a chosen input set
load_marks(path, r1cs)  -> wire/constraint -> source section, free wires

Paths: the pinned r1cs files are read from $VERIF_WORK/r1cs and every generated
file goes to $VERIF_WORK/out (default VERIF_WORK: verification/work).
"""
import json
import os
import struct
import sys
from bisect import bisect_right

VERIF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.abspath(os.environ.get('VERIF_WORK', os.path.join(VERIF_DIR, 'work')))
R1CS_DIR = os.path.join(WORK, 'r1cs')
OUT = os.path.join(WORK, 'out')

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


class R1CS:
    def __init__(self, n_wires, n_pubout, n_pubin, n_prvin, constraints):
        self.n_wires = n_wires
        self.n_pubout = n_pubout
        self.n_pubin = n_pubin
        self.n_prvin = n_prvin
        self.constraints = constraints  # list of (A, B, C), each dict wire -> coeff

    def write(self, path, order, n_pubout, n_pubin, n_prvin):
        """Write a wire-permuted copy. order[new] = old wire id; labels = old ids."""
        assert order[0] == 0 and sorted(order) == list(range(self.n_wires))
        new_of = [0] * self.n_wires
        for new, old in enumerate(order):
            new_of[old] = new
        cons = bytearray()
        for lcs in self.constraints:
            for lc in lcs:
                items = sorted((new_of[w], c) for w, c in lc.items())
                cons += struct.pack('<I', len(items))
                for w, c in items:
                    cons += struct.pack('<I', w) + (c % P).to_bytes(32, 'little')
        header = struct.pack('<I', 32) + P.to_bytes(32, 'little')
        header += struct.pack('<IIII', self.n_wires, n_pubout, n_pubin, n_prvin)
        header += struct.pack('<Q', self.n_wires) + struct.pack('<I', len(self.constraints))
        w2l = b''.join(struct.pack('<Q', old) for old in order)
        out = bytearray(b'r1cs') + struct.pack('<II', 1, 3)
        for kind, sec in ((1, header), (2, bytes(cons)), (3, w2l)):
            out += struct.pack('<IQ', kind, len(sec)) + sec
        with open(path, 'wb') as f:
            f.write(out)

    def subsystem(self, cons_idx, inputs, path):
        """Write the sub-r1cs made of constraints cons_idx. `inputs` (old ids,
        excluding 0) become private inputs; every other wire that occurs is a
        target. Returns the new->old order."""
        used = set()
        for i in cons_idx:
            for lc in self.constraints[i]:
                used.update(lc)
        used.discard(0)
        ins = sorted(w for w in used if w in inputs)
        rest = sorted(w for w in used if w not in inputs)
        order = [0] + ins + rest
        new_of = {old: new for new, old in enumerate(order)}
        sub = R1CS(len(order), 0, 0, len(ins),
                   [tuple({new_of[w]: c for w, c in lc.items()} for lc in self.constraints[i])
                    for i in cons_idx])
        sub.write(path, list(range(len(order))), 0, 0, len(ins))
        # rewrite labels to old ids
        with open(path, 'rb') as f:
            data = bytearray(f.read())
        tail = b''.join(struct.pack('<Q', old) for old in order)
        data[-len(tail):] = tail
        with open(path, 'wb') as f:
            f.write(data)
        return order


def parse(path):
    data = open(path, 'rb').read()
    assert data[:4] == b'r1cs'
    version, nsec = struct.unpack_from('<II', data, 4)
    pos = 12
    sections = {}
    for _ in range(nsec):
        kind, size = struct.unpack_from('<IQ', data, pos)
        pos += 12
        sections[kind] = (pos, size)
        pos += size
    hp, _ = sections[1]
    fs = struct.unpack_from('<I', data, hp)[0]
    prime = int.from_bytes(data[hp + 4:hp + 4 + fs], 'little')
    assert prime == P
    q = hp + 4 + fs
    n_wires, n_pubout, n_pubin, n_prvin = struct.unpack_from('<IIII', data, q)
    n_labels = struct.unpack_from('<Q', data, q + 16)[0]
    m = struct.unpack_from('<I', data, q + 24)[0]
    cp, _ = sections[2]
    constraints = []
    for _ in range(m):
        lcs = []
        for _ in range(3):
            n = struct.unpack_from('<I', data, cp)[0]
            cp += 4
            lc = {}
            for _ in range(n):
                w = struct.unpack_from('<I', data, cp)[0]
                c = int.from_bytes(data[cp + 4:cp + 36], 'little')
                cp += 36
                lc[w] = c
            lcs.append(lc)
        constraints.append(tuple(lcs))
    return R1CS(n_wires, n_pubout, n_pubin, n_prvin, constraints)


class Marks:
    def __init__(self, path):
        doc = json.load(open(path))
        self.num_instance = doc['num_instance']
        self.sections = [(mk['label'], mk['wit'], mk['cons']) for mk in doc['marks'] if mk['kind'] == 'section']
        self.free = [(mk['label'], mk['start'] + self.num_instance, mk['end'] + self.num_instance)
                     for mk in doc['marks'] if mk['kind'] == 'free']
        self._wit_starts = [s[1] + self.num_instance for s in self.sections]
        self._cons_starts = [s[2] for s in self.sections]

    def wire_section(self, w):
        if w < self.num_instance:
            return 'public input' if w else 'constant one'
        i = bisect_right(self._wit_starts, w) - 1
        # sections can be empty (no witness); bisect picks the last one starting <= w
        return self.sections[i][0] if i >= 0 else '?'

    def cons_section(self, c):
        i = bisect_right(self._cons_starts, c) - 1
        return self.sections[i][0] if i >= 0 else '?'

    def free_wires(self):
        out = {}
        for label, s, e in self.free:
            for w in range(s, e):
                out[w] = label
        return out

    def section_ranges(self):
        """[(label, wire_start, wire_end, cons_start, cons_end)] in r1cs wire ids."""
        out = []
        for i, (label, w, c) in enumerate(self.sections):
            if i + 1 < len(self.sections):
                w2, c2 = self.sections[i + 1][1], self.sections[i + 1][2]
            else:
                w2, c2 = w, c
            out.append((label, w + self.num_instance, w2 + self.num_instance, c, c2))
        return out


if __name__ == '__main__':
    r = parse(sys.argv[1])
    print(r.n_wires, r.n_pubout, r.n_pubin, r.n_prvin, len(r.constraints))
