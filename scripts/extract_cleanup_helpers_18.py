#!/usr/bin/env python3
"""R18-C compact static evidence, from pinned private inputs; Capstone 5.0.7."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST_SHA = 'fc4f2070cb0efa89c9473ebe507d0e2d3f01e1f5f66338177be5f34848ee7151'
PREFLIGHT_SHA = '8749c47798c3758dc7509d0b3b71b7147f169ee0390066f01ef023baf670bcbb'
OWNED = [(0x68d010, 10), (0x68d1f0, 138), (0x946323, 24)]
# Selected instructions only; all body instructions are compared in memory.
SELECTED = {
    0x68d010: [0x68d010, 0x68d013, 0x68d018],
    0x68d1f0: [0x68d1f5, 0x68d1ff, 0x68d203, 0x68d207, 0x68d209,
        0x68d20b, 0x68d226, 0x68d231, 0x68d23c, 0x68d247,
        0x68d24d, 0x68d257, 0x68d25e, 0x68d265, 0x68d271],
    0x946323: [0x946323, 0x946329, 0x94632c, 0x94632f, 0x946332],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def norm(text):
    text = text.lower()
    # Identical one-byte string comparison, with source/destination spelling swapped.
    if text in ('cmpsb.repe es:edi,esi',
                'repe cmpsb byte ptr [esi], byte ptr es:[edi]'):
        return 'repe_cmpsb_ds_esi_es_edi'
    text = re.sub(r'\bjz\b', 'je', text)
    text = re.sub(r'\bjnz\b', 'jne', text)
    text = re.sub(r'\b0x[0-9a-f]+\b', lambda m: str(int(m[0], 16)), text)
    return re.sub(r'\s+', '', text).replace('+0]', ']').replace('+-', '-')


def extract(binary, native, preflight):
    assert capstone.__version__ == '5.0.7', 'requires Capstone 5.0.7'
    data = binary.read_bytes()
    assert digest(data) == SHA, 'wrong specimen'
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[:2] == b'MZ' and data[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H', data, pe+4)[0] == 0x14c
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
    assert manifest['preflight_sha256'] == PREFLIGHT_SHA
    assert manifest['checkpoint_archive_sha256'] == 'dcde69cbad630e36cc9779c1fcd5dbe3b4802ed4e51c3fa0d8e559b7e9381cd3'
    for name, entry in manifest['files'].items():
        content = (native/name).read_bytes()
        assert len(content) == entry['bytes'] and digest(content) == entry['sha256'], name
    preflight_data = preflight.read_bytes()
    assert digest(preflight_data) == PREFLIGHT_SHA, 'wrong annotation preflight'
    receipt = json.loads(preflight_data)
    assert receipt['sha256'] == SHA
    old = {r['address']: r for r in receipt['sites'] if r['instruction_exists']}
    bodies = []
    for start, length in OWNED:
        name = f'{start:08x}'
        assert old[name]['function_name'] == 'FUN_'+name
        assert old[name].get('function_comment') in (None, '')
        off = offset(start, length)
        raw = data[off:off+length]
        instructions = list(md.disasm(raw, start))
        assert instructions and instructions[0].address == start
        assert instructions[-1].address+instructions[-1].size == start+length
        assert sum(i.size for i in instructions) == length
        mapping = {i.address: (i.mnemonic+' '+i.op_str).strip() for i in instructions}
        lines = (native/(name+'.asm')).read_text().splitlines()
        listing = {int(line[:8], 16): line[10:] for line in lines if line}
        assert len(listing) == len([line for line in lines if line])
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
            'native_comparison': {'all_instructions_match': True,
                'all_local_branch_targets_are_instruction_starts': True,
                'export_sha256': {name+ext: digest((native/(name+ext)).read_bytes()) for ext in ('.asm', '.c')}},
        })
    # Boundary context only: establish the forwarded argument's normal stack balance.
    # Do not decode the larger, noncontiguous 0094633b body as an owned contract.
    context = []
    for address, length, expected in [(0x944c94, 4, 'push dword ptr [esp + 4]'),
                                       (0x944c98, 5, 'call 0x9452ca'),
                                       (0x944c9d, 2, 'pop ecx; ret'),
                                       (0x946396, 3, 'ret 0x10')]:
        raw = data[offset(address, length):offset(address, length)+length]
        ins = list(md.disasm(raw, address))
        actual = '; '.join((i.mnemonic+' '+i.op_str).strip() for i in ins)
        assert actual == expected and sum(i.size for i in ins) == length
        context.append({'site': f'{address:08x}', 'file_offset': f'{offset(address, length):08x}',
                        'instruction': actual, 'scope': 'Immediate boundary context only'})
    return {
        'schema_version': 1, 'specimen_sha256': SHA,
        'baseline_commit': '267756ebe6d797b6477efd5f829d45ed6cb54d07',
        'native_checkpoint': '2026-10-18-investigation-17',
        'address_kind': 'PE virtual addresses unless file_offset is explicit; field offsets in bytes',
        'method': 'Capstone 5.0.7 full local body decode and all-instruction native comparison; static, no execution',
        'private_export_manifest_sha256': MANIFEST_SHA,
        'private_annotation_preflight_sha256': PREFLIGHT_SHA,
        'verified_old_names': {f'{a:08x}': old[f'{a:08x}']['function_name'] for a, _ in OWNED},
        'verified_old_comments': {f'{a:08x}': '' for a, _ in OWNED},
        'normalization': 'Jump aliases, numeric spelling, whitespace, plus-negative spelling and equivalent REPE CMPSB operand order/implicit byte width; other operand widths preserved',
        'owned_bodies': bodies, 'context_only': context,
        'limitations': ['No execution oracle; callees and exception handlers remain boundaries.',
            'Short forwarding and frame-dependent helpers are local mechanics, not complete lifetime contracts.',
            'No full scouting workflow, allocator compatibility or alias/lifetime/failure-safety guarantee.'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--native-dir', required=True, type=Path)
    parser.add_argument('--preflight', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.write_bytes((json.dumps(extract(args.binary, args.native_dir, args.preflight), indent=2)+'\n').encode('utf-8'))
    print('R18-C: three complete bodies, every native instruction and all local branch targets verified')
