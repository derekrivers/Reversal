#!/usr/bin/env python3
"""R17-C deterministic compact static evidence; requires Capstone 5.0.7."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST_SHA = '096c06e07891855555057cdcc9f33307c6cdee79e7c632be5f593f76d894a2b8'
PREFLIGHT_SHA = '0d084f0348af44eeb24a73d8cec0fc866525099b14180bd87bd9c6246beda10f'
OWNED = [(0x68d040, 51), (0x9462bb, 104), (0x7ae4f0, 124)]
# Selected sites, not a retained listing. All instructions are checked in memory.
SELECTED = {
    0x68d040: [0x68d043, 0x68d04c, 0x68d051, 0x68d054, 0x68d058,
        0x68d05f, 0x68d068, 0x68d06a],
    0x9462bb: [0x9462de, 0x9462e2, 0x9462e7, 0x9462eb, 0x9462ee,
        0x9462f2, 0x9462f7, 0x9462fa, 0x946302, 0x946309, 0x946315],
    0x7ae4f0: [0x7ae50e, 0x7ae514, 0x7ae520, 0x7ae529, 0x7ae533,
        0x7ae53d, 0x7ae53e, 0x7ae548, 0x7ae551, 0x7ae561],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def norm(text):
    text = text.lower()
    text = re.sub(r'\bjz\b', 'je', text)
    text = re.sub(r'\bjnz\b', 'jne', text)
    text = text.replace('mov eax,fs:[', 'mov eax,dword ptr fs:[')
    text = re.sub(r'\b0x[0-9a-f]+\b', lambda m: str(int(m[0], 16)), text)
    return re.sub(r'\s+', '', text).replace('+0]', ']').replace('+-', '-')


def extract(binary, native, preflight):
    assert capstone.__version__ == '5.0.7', 'requires Capstone 5.0.7'
    data = binary.read_bytes()
    assert digest(data) == SHA, 'wrong specimen'
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[:2] == b'MZ' and data[pe:pe+4] == b'PE\0\0'
    opt = pe+24
    assert struct.unpack_from('<H', data, opt)[0] == 0x10b
    base = struct.unpack_from('<I', data, opt+28)[0]
    count = struct.unpack_from('<H', data, pe+6)[0]
    size = struct.unpack_from('<H', data, pe+20)[0]
    sections = [struct.unpack_from('<8sIIII', data, opt+size+40*i) for i in range(count)]

    def offset(va, length):
        for _, _, rva, rawsize, raw in sections:
            delta = va-base-rva
            if 0 <= delta and delta+length <= rawsize:
                return raw+delta
        raise ValueError(f'unbacked VA {va:x}')

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    manifest_data = (native/'manifest.json').read_bytes()
    assert digest(manifest_data) == MANIFEST_SHA, 'wrong native manifest'
    manifest = json.loads(manifest_data)
    assert manifest['specimen_sha256'] == SHA
    for name, entry in manifest['files'].items():
        content = (native/name).read_bytes()
        assert len(content) == entry['bytes'] and digest(content) == entry['sha256'], name
    preflight_data = preflight.read_bytes()
    assert digest(preflight_data) == PREFLIGHT_SHA, 'wrong annotation preflight'
    receipt = json.loads(preflight_data)
    assert receipt['sha256'] == SHA
    old_names = {r['address']: r['function_name'] for r in receipt['sites'] if r['instruction_exists']}
    bodies = []
    for start, length in OWNED:
        name = f'{start:08x}'
        assert old_names[name] == 'FUN_'+name
        off = offset(start, length)
        raw = data[off:off+length]
        instructions = list(md.disasm(raw, start))
        assert instructions and instructions[0].address == start
        assert instructions[-1].address+instructions[-1].size == start+length
        assert sum(i.size for i in instructions) == length
        mapping = {i.address: (i.mnemonic+' '+i.op_str).strip() for i in instructions}
        listing = {int(line[:8], 16): line[10:] for line in (native/(name+'.asm')).read_text().splitlines() if line}
        left = {a: norm(t) for a, t in mapping.items()}
        right = {a: norm(t) for a, t in listing.items()}
        assert left == right, [(hex(a), left.get(a), right.get(a)) for a in left.keys() | right.keys() if left.get(a) != right.get(a)]
        branches = [i for i in instructions if i.mnemonic.startswith('j')]
        assert all(int(i.op_str, 16) in mapping for i in branches), 'nonlocal or unaligned branch'
        bodies.append({
            'entry_va': name, 'end_exclusive_va': f'{start+length:08x}',
            'file_offset': f'{off:08x}', 'length_bytes': length,
            'body_sha256': digest(raw), 'instruction_count': len(instructions),
            'selected_sites': {f'{a:08x}': mapping[a] for a in SELECTED[start]},
            'all_calls': [{'site': f'{i.address:08x}', 'target': i.op_str} for i in instructions if i.mnemonic == 'call'],
            'all_branches': [{'site': f'{i.address:08x}', 'instruction': mapping[i.address]} for i in branches],
            'all_returns': [{'site': f'{i.address:08x}', 'instruction': mapping[i.address]} for i in instructions if i.mnemonic.startswith('ret')],
            'native_comparison': {'all_instructions_match': True, 'all_local_branch_targets_are_instruction_starts': True,
                'export_sha256': {name+ext: digest((native/(name+ext)).read_bytes()) for ext in ('.asm', '.c')}},
        })
    return {
        'schema_version': 1, 'specimen_sha256': SHA,
        'baseline_commit': 'edc2a3cafe3695346e706733100eeff59be5b9f4',
        'native_checkpoint': '2026-10-18-investigation-16',
        'address_kind': 'PE virtual addresses unless file_offset is explicit; field offsets in bytes',
        'method': 'Capstone 5.0.7 full local body decode and all-instruction native comparison; static, no execution',
        'private_export_manifest_sha256': MANIFEST_SHA,
        'private_annotation_preflight_sha256': PREFLIGHT_SHA,
        'verified_old_names': {f'{a:08x}': old_names[f'{a:08x}'] for a, _ in OWNED},
        'normalization': 'Jump aliases, numeric spelling, whitespace, EAX FS DWORD qualifier and plus-negative spelling; operand widths preserved',
        'owned_bodies': bodies,
        'limitations': ['Callees, indirect callback implementations and exception handlers remain boundaries; no execution oracle.',
            'No full scouting workflow, complete nested ownership, lifetime/alias safety or recoverable failure guarantee.'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--native-dir', required=True, type=Path)
    parser.add_argument('--preflight', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.write_bytes((json.dumps(extract(args.binary, args.native_dir, args.preflight), indent=2)+'\n').encode('utf-8'))
    print('R17-C: three complete bodies, every native instruction and all local branch targets verified')
