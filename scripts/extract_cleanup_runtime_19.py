#!/usr/bin/env python3
"""R19-C static evidence: pinned PE32, Capstone 5.0.7, full native comparison."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST_SHA = '3c5da196118b891f3dcd84f8126355d3c36888c3c7b72ca1f6d89772d8a22935'
PREFLIGHT_SHA = 'a8b6f47a04ac2dcc2d6fb13537a55b223db5630d50e857ceb014f40f7069cf78'
CHECKPOINT_SHA = 'a316ec083e9658460c115581746e9e69da856e9c76c5fb24c516670b3b34d6ec'
# Half-open ranges. 00946377..00946383 is not in the native function body.
OWNED = {
    0x94633b: [(0x94633b, 0x946377), (0x946384, 0x946399)],
    0x9452ca: [(0x9452ca, 0x945333)],
    0x948b90: [(0x948b90, 0x948bbb)],
    0x9498eb: [(0x9498eb, 0x949942)],
    0x949942: [(0x949942, 0x949987)],
}
SELECTED = {
    0x94633b: [0x946351, 0x946360, 0x946364, 0x94636c, 0x94636f, 0x946372, 0x94638b, 0x946396],
    0x9452ca: [0x9452d2, 0x9452d6, 0x9452e1, 0x9452ed, 0x945304, 0x945317, 0x945324, 0x94532a],
    0x948b90: [0x948b95, 0x948b9d, 0x948ba8, 0x948bab, 0x948bb3],
    0x9498eb: [0x9498f7, 0x9498fc, 0x949909, 0x949914, 0x949922, 0x94992a, 0x949931, 0x949939],
    0x949942: [0x94994a, 0x94994d, 0x949950, 0x949958, 0x94995b, 0x94995d, 0x949960, 0x949966, 0x94996f, 0x949975, 0x949980],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def norm(text):
    text = text.lower()
    for old, new in [('jz', 'je'), ('jnz', 'jne'), ('jnc', 'jae'), ('jc', 'jb')]:
        text = re.sub(r'\b'+old+r'\b', new, text)
    # Ghidra omits width for the accumulator MOV absolute-memory encoding.
    text = re.sub(r'^mov eax,(\[|fs:)', r'mov eax,dword ptr \1', text)
    text = re.sub(r'\b0x[0-9a-f]+\b', lambda m: str(int(m[0], 16)), text)
    text = re.sub(r'\s+', '', text).replace('+-', '-')
    return re.sub(r'\*1(?=\+|\]|-|$)', '', text)


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

    def offset(va, length=1):
        for _, _, rva, rawsize, raw in sections:
            delta = va-base-rva
            if 0 <= delta and delta+length <= rawsize:
                return raw+delta
        raise ValueError(f'unbacked VA {va:x}')

    def u32(va):
        return struct.unpack_from('<I', data, offset(va, 4))[0]

    def cstring(va):
        off = offset(va)
        return data[off:data.index(0, off)].decode('ascii')

    manifest_data = (native/'manifest.json').read_bytes()
    assert digest(manifest_data) == MANIFEST_SHA, 'wrong native manifest'
    manifest = json.loads(manifest_data)
    assert manifest['specimen_sha256'] == SHA
    assert manifest['preflight_sha256'] == PREFLIGHT_SHA
    assert manifest['checkpoint_archive_sha256'] == CHECKPOINT_SHA
    for name, entry in manifest['files'].items():
        content = (native/name).read_bytes()
        assert len(content) == entry['bytes'] and digest(content) == entry['sha256'], name
    preflight_data = preflight.read_bytes()
    assert digest(preflight_data) == PREFLIGHT_SHA, 'wrong annotation preflight'
    receipt = json.loads(preflight_data)
    assert receipt['sha256'] == SHA
    old = {r['address']: r for r in receipt['sites'] if r['instruction_exists']}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    bodies = []
    for start, ranges in OWNED.items():
        name = f'{start:08x}'
        assert old[name]['function_name'] == 'FUN_'+name
        assert old[name].get('function_comment') in (None, '')
        instructions, ranges_out, combined = [], [], b''
        for begin, end in ranges:
            off = offset(begin, end-begin)
            raw = data[off:off+end-begin]
            ins = list(md.disasm(raw, begin))
            assert ins and ins[0].address == begin
            assert ins[-1].address+ins[-1].size == end
            assert sum(i.size for i in ins) == end-begin
            instructions.extend(ins)
            combined += raw
            ranges_out.append({'start_va': f'{begin:08x}', 'end_exclusive_va': f'{end:08x}',
                               'file_offset': f'{off:08x}', 'length_bytes': end-begin,
                               'sha256': digest(raw)})
        mapping = {i.address: (i.mnemonic+' '+i.op_str).strip() for i in instructions}
        lines = (native/(name+'.asm')).read_text().splitlines()
        listing = {int(line[:8], 16): line[10:] for line in lines if line}
        assert len(listing) == len([line for line in lines if line])
        left = {a: norm(t) for a, t in mapping.items()}
        right = {a: norm(t) for a, t in listing.items()}
        assert left == right, [(hex(a), left.get(a), right.get(a)) for a in left.keys() | right.keys() if left.get(a) != right.get(a)]
        branches = [i for i in instructions if i.mnemonic.startswith('j')]
        assert all(int(i.op_str, 16) in mapping for i in branches)
        bodies.append({
            'entry_va': name, 'ranges': ranges_out, 'length_bytes': len(combined),
            'ordered_range_concatenation_sha256': digest(combined), 'instruction_count': len(instructions),
            'selected_sites': {f'{a:08x}': mapping[a] for a in SELECTED[start]},
            'all_calls': [{'site': f'{i.address:08x}', 'target': i.op_str} for i in instructions if i.mnemonic == 'call'],
            'all_branches': [{'site': f'{i.address:08x}', 'instruction': mapping[i.address]} for i in branches],
            'all_returns': [{'site': f'{i.address:08x}', 'instruction': mapping[i.address]} for i in instructions if i.mnemonic.startswith('ret')],
            'native_comparison': {'all_instructions_match': True, 'all_branch_targets_are_owned_instruction_starts': True,
                'export_sha256': {name+ext: digest((native/(name+ext)).read_bytes()) for ext in ('.asm', '.c')}},
        })
    # Import identity is PE metadata, not a claim about imported behavior.
    descriptor = base+struct.unpack_from('<I', data, opt+104)[0]
    import_match = []
    while any(data[offset(descriptor, 20):offset(descriptor, 20)+20]):
        original, _, _, dll, iat = struct.unpack_from('<5I', data, offset(descriptor, 20))
        index = 0
        while (value := u32(base+(original or iat)+4*index)):
            if base+iat+4*index == 0x96715c:
                assert not value & 0x80000000
                import_match.append({'iat_va': '0096715c', 'dll': cstring(base+dll),
                                     'symbol': cstring(base+value+2)})
            index += 1
        descriptor += 20
    assert import_match == [{'iat_va': '0096715c', 'dll': 'KERNEL32.dll', 'symbol': 'HeapFree'}]
    # Scope metadata explains the noncontiguous body; excluded code is not coverage.
    scope = [u32(0x9713e0+4*i) for i in range(3)]
    assert scope == [0xffffffff, 0x946377, 0x946381]
    return {
        'schema_version': 1, 'specimen_sha256': SHA,
        'baseline_commit': '0ab803b3adb19eb9ecdb70d4a31d759127376b78',
        'native_checkpoint': '2026-10-18-investigation-18',
        'address_kind': 'PE virtual addresses unless file_offset is explicit; field offsets in bytes',
        'method': 'Capstone 5.0.7 complete included-range decode and all-instruction native comparison; static, no execution',
        'private_export_manifest_sha256': MANIFEST_SHA,
        'private_annotation_preflight_sha256': PREFLIGHT_SHA,
        'verified_old_names': {f'{a:08x}': old[f'{a:08x}']['function_name'] for a in OWNED},
        'preflight_comment_values': {f'{a:08x}': old[f'{a:08x}'].get('function_comment') for a in OWNED},
        'normalization': 'Jump aliases, numeric and whitespace spelling, plus-negative displacements, scale one, implicit accumulator-MOV dword width; all other operand widths retained',
        'owned_bodies': bodies,
        'excluded_hole': {'start_va': '00946377', 'end_exclusive_va': '00946384', 'length_bytes': 13,
            'reason': 'Outside native body; scope-table targets 00946377 and 00946381 are transitive exception boundaries'},
        'scope_metadata_only': {'va': '009713e0', 'dwords': [f'{v:08x}' for v in scope]},
        'import_metadata_only': import_match,
        'limitations': ['No execution oracle or complete exception-handler contract.',
            'Larger callees, imported API implementation and callback behavior remain boundaries.',
            'No complete allocator/lifetime, valid-alias, reentrancy or thread-safety guarantee.'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--native-dir', required=True, type=Path)
    parser.add_argument('--preflight', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = extract(args.binary, args.native_dir, args.preflight)
    args.output.write_bytes((json.dumps(result, indent=2)+'\n').encode('utf-8'))
    print('R19-C: five bodies, 385 included bytes, all native instructions and branch targets verified')
