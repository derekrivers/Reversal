#!/usr/bin/env python3
"""R16-C deterministic compact static evidence; requires Capstone 5.0.7."""

# Integrity assertions must remain active before reading or writing evidence.
if not __debug__:
    raise SystemExit("Integrity checks require assertions; rerun without Python optimization (-O/-OO).")
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST_SHA = 'fc92c27bcc9f2f15bedebb4aadbebba7bf0ed5f8801c787e2f0e262c48a7e960'
PREFLIGHT_SHA = '2be810e149b9d5ebe8de028bf9542aab932afd31514e2ec8d737bef8450374bc'
OWNED = [(0x7b7690, 421), (0x813140, 120)]
# Selected sites, not a retained listing. All instructions are checked in memory.
SELECTED = {
    0x7b7690: [0x7b76ad, 0x7b76b3, 0x7b76be, 0x7b76c6, 0x7b76cc,
        0x7b76d7, 0x7b76dc, 0x7b76e2, 0x7b76ea, 0x7b76f0, 0x7b76f7,
        0x7b7700, 0x7b7702, 0x7b7710, 0x7b7713, 0x7b7717, 0x7b771f,
        0x7b7750, 0x7b7780, 0x7b7794, 0x7b7796, 0x7b779b, 0x7b77a5,
        0x7b77ab, 0x7b77ae, 0x7b77b0, 0x7b77b5, 0x7b77b8, 0x7b77bc,
        0x7b77bf, 0x7b77c1, 0x7b77cb, 0x7b77d0, 0x7b77ed, 0x7b77f4,
        0x7b77fd, 0x7b7804, 0x7b7806, 0x7b780b, 0x7b7814, 0x7b7832],
    0x813140: [0x813157, 0x81315d, 0x81316b, 0x813170, 0x813175,
        0x813177, 0x81317d, 0x813188, 0x81318d, 0x813192, 0x813194,
        0x813195, 0x8131a3, 0x8131b7],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def norm(text):
    text = text.lower()
    text = re.sub(r'\bjz\b', 'je', text)
    text = re.sub(r'\bjnz\b', 'jne', text)
    text = text.replace('mov eax,fs:[', 'mov eax,dword ptr fs:[')
    text = text.replace('movsd.rep es:edi,esi', 'rep movsd dword ptr es:[edi],dword ptr [esi]')
    text = text.replace('movsb.rep es:edi,esi', 'rep movsb byte ptr es:[edi],byte ptr [esi]')
    text = re.sub(r'\b0x[0-9a-f]+\b', lambda m: str(int(m[0], 16)), text)
    return re.sub(r'\s+', '', text).replace('+0]', ']').replace('*1', '').replace('+-', '-')


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
        'baseline_commit': '15eb7357500cf2dfd1838487e2a28e05d4965410',
        'native_checkpoint': '2026-10-18-investigation-15',
        'address_kind': 'PE virtual addresses unless file_offset is explicit; field offsets in bytes',
        'method': 'Capstone 5.0.7 full local body decode and all-instruction native comparison; static, no execution',
        'private_export_manifest_sha256': MANIFEST_SHA,
        'private_annotation_preflight_sha256': PREFLIGHT_SHA,
        'verified_old_names': {f'{a:08x}': old_names[f'{a:08x}'] for a, _ in OWNED},
        'normalization': 'Jump aliases, numeric spelling, whitespace, EAX FS DWORD qualifier, scale-one and plus-negative spelling, REP MOVSD/MOVSB rendering; operand widths preserved',
        'owned_bodies': bodies,
        'limitations': ['Callees and exception handlers remain boundaries; no execution oracle.',
            'No full scouting persistence, complete nested ownership, overlap/self-copy safety or transaction claim.'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--native-dir', required=True, type=Path)
    parser.add_argument('--preflight', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.write_bytes((json.dumps(extract(args.binary, args.native_dir, args.preflight), indent=2)+'\n').encode('utf-8'))
    print('R16-C: both complete bodies, every native instruction and all local branch targets verified')
