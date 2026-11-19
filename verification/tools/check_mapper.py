"""Require verbatim production function bodies, ignoring only sec/free marker lines."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'protocol/rust/crates/zkapi-proof/src/groth16.rs').read_text()
mapper = (ROOT / 'verification/mapper/src/circuits.rs').read_text()
mapper = re.sub(r'^\s*(?:sec|free)\([^\n]*\);\n', '', mapper, flags=re.M)


def body(text, name, implementation=None):
    if implementation:
        text = text[text.index(f'impl ConstraintSynthesizer<CircuitField> for {implementation} {{'):]
    match = re.search(r'\bfn ' + name + r'\(', text)
    assert match, name
    start = text.index('{', match.end())
    depth = 1
    end = start + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    # Marker removal can remove adjacent blank lines, not source statements.
    return '\n'.join(line for line in text[start:end].splitlines() if line.strip())


for name in ('poseidon_config', 'poseidon_hash_var', 'domain', 'domain_var',
             'scalar_bits_witness', 'signing_key_input', 'enforce_deployment',
             'commitment_var', 'enforce_signature', 'enforce_anchor_chain'):
    assert body(source, name) == body(mapper, name), f'{name}: mapper body drift'
    print(f'verbatim helper: {name}')
for native, marked in (('RequestCircuit', 'MarkedRequest'),
                       ('WithdrawalCircuit', 'MarkedWithdrawal'),
                       ('SolanaTransitionCircuit', 'MarkedTransition')):
    assert body(source, 'generate_constraints', native) == body(mapper, 'generate_constraints', marked), native
    print(f'verbatim circuit: {native}')
