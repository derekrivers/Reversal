#!/usr/bin/env python3
"""Verify R26-C full local PE/native operands and external switch-table CFG."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST = 'e86692ed3575e204e9e22c5c6d15bba0f5a299d1bc30ce64111b25f0e66cad75'
PREFLIGHT = 'b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd'
CHECKPOINT = '670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a'
ENTRY, SIZE, TABLE = 0x6834f0, 178, 0x6835a4
TARGETS = [0x683550, 0x68356a, 0x683586, 0x683592, 0x683578]
TABLE_SHA = 'db1835fa55fd6b84aa49555e828ac096edf165e009215802a8cfc5abf01d8c7e'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(n):
    return f'{n:08x}'


def normalized(s):
    s = re.sub(r'0x[0-9a-f]+', lambda m: str(int(m[0], 16)), s.lower().strip())
    s = re.sub(r'\s+', '', s).replace('*0x1', '').replace('*1', '')
    for a, b in [('jz', 'je'), ('jnz', 'jne')]:
        if s.startswith(a):
            s = b+s[len(a):]
    # Ghidra leaves the absolute MOV accumulator operand size implicit.
    return s.replace('moveax,[', 'moveax,dwordptr[')


def pe_offset(pe, va, size):
    header = struct.unpack_from('<I', pe, 0x3c)[0]
    need(pe[:2] == b'MZ' and pe[header:header+4] == b'PE\0\0', 'invalid PE')
    need(struct.unpack_from('<H', pe, header+4)[0] == 0x14c and
         struct.unpack_from('<H', pe, header+24)[0] == 0x10b, 'requires PE32 x86')
    count, opt_size = struct.unpack_from('<H', pe, header+6)[0], struct.unpack_from('<H', pe, header+20)[0]
    base = struct.unpack_from('<I', pe, header+24+28)[0]
    sections = [struct.unpack_from('<8sIIII', pe, header+24+opt_size+40*i) for i in range(count)]
    matches = [off+va-base-rva for _, virtual, rva, raw, off in sections
               if 0 <= va-base-rva and va-base-rva+size <= min(virtual, raw)]
    need(len(matches) == 1, 'range is not uniquely raw-backed')
    return matches[0]


def extract(binary, exports, preflight):
    need(capstone.__version__ == '5.0.7', 'requires Capstone 5.0.7')
    pe = binary.read_bytes()
    need(len(pe) == 7192576 and sha(pe) == SPECIMEN, 'pinned specimen mismatch')
    manifest_raw, old_raw = (exports/'manifest.json').read_bytes(), preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST and sha(old_raw) == PREFLIGHT, 'native manifest/preflight SHA-256 mismatch')
    manifest, old = json.loads(manifest_raw), json.loads(old_raw)
    need(manifest['specimen_sha256'] == old['sha256'] == SPECIMEN and
         manifest['checkpoint_archive_sha256'] == CHECKPOINT and
         manifest['preflight_sha256'] == PREFLIGHT, 'native provenance mismatch')
    need(set(manifest['files']) == {hx(a)+ext for a in [0x62be00, 0x62e700, ENTRY, 0x7160e0, 0x9466d0]
                                  for ext in ['.asm', '.c']}, 'native export inventory mismatch')
    for name, meta in manifest['files'].items():
        raw = (exports/name).read_bytes()
        need(len(raw) == meta['bytes'] and sha(raw) == meta['sha256'], 'native export mismatch: '+name)
    sites = {int(s['address'], 16): s for s in old['sites']}
    need(len(sites) == 5 and sites[ENTRY] == {'address': hx(ENTRY), 'function_name': 'FUN_006834f0',
         'instruction_exists': True, 'body_addresses': SIZE}, 'exact-old native name/body mismatch')
    off, table_off = pe_offset(pe, ENTRY, SIZE), pe_offset(pe, TABLE, 20)
    body, table = pe[off:off+SIZE], pe[table_off:table_off+20]
    need(sha(table) == TABLE_SHA and list(struct.unpack('<5I', table)) == TARGETS, 'switch-table bytes/targets mismatch')
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    ins = list(md.disasm(body, ENTRY))
    need(sum(i.size for i in ins) == SIZE and ins[-1].address+ins[-1].size == ENTRY+SIZE, 'incomplete body decode')
    native = [(int(m[1], 16), m[2]) for m in re.finditer(r'^([0-9a-fA-F]{8})\s+(.+)$',
              (exports/'006834f0.asm').read_text(encoding='utf-8-sig'), re.M)]
    need(len(native) == len(ins), 'native instruction count differs')
    starts = {i.address for i in ins}
    edges, branches, reads = {}, {}, []
    for i, (address, line) in zip(ins, native):
        need(i.address == address and normalized(i.mnemonic+' '+i.op_str) == normalized(line),
             'native PE operand mismatch at '+hx(i.address))
        need(i.mnemonic != 'call', 'unexpected callee')
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM and i.mnemonic != 'lea':
                need(op.access == capstone.CS_AC_READ, 'unexpected explicit memory write')
                reads.append({'va': hx(i.address), 'width': op.size, 'operand': i.op_str})
        if i.mnemonic == 'ret':
            need(not i.op_str, 'unexpected return stack immediate')
            targets = []
        elif i.mnemonic.startswith('j'):
            if i.address == 0x683549:
                need(i.mnemonic == 'jmp' and len(i.operands) == 1 and
                     i.operands[0].type == capstone.x86.X86_OP_MEM and
                     i.operands[0].size == 4 and i.operands[0].mem.base == 0 and
                     i.operands[0].mem.index == capstone.x86.X86_REG_EAX and
                     i.operands[0].mem.scale == 4 and i.operands[0].mem.disp == TABLE,
                     'indirect dispatch operand changed')
                targets = TARGETS
            else:
                need(len(i.operands) == 1 and i.operands[0].type == capstone.x86.X86_OP_IMM,
                     'unexpected indirect branch')
                targets = [i.operands[0].imm]
                if i.mnemonic != 'jmp':
                    targets.append(i.address+i.size)
            branches[hx(i.address)] = [hx(a) for a in targets]
        else:
            targets = [i.address+i.size]
        need(all(a in starts for a in targets), 'CFG escapes or enters non-instruction boundary')
        edges[i.address] = targets
    reachable, pending = set(), [ENTRY]
    while pending:
        a = pending.pop()
        if a not in reachable:
            reachable.add(a)
            pending.extend(edges[a])
    need(reachable == starts, 'unreachable native body instructions')
    need({i.address for i in ins if i.mnemonic == 'ret'} == {0x683527, 0x6835a1}, 'return inventory changed')
    return {'schema_version': 1, 'unit': 'R26-C', 'entry_va': hx(ENTRY), 'old_native_name': 'FUN_006834f0',
            'specimen_sha256': SPECIMEN, 'checkpoint_archive_sha256': CHECKPOINT,
            'export_manifest_sha256': MANIFEST, 'annotation_preflight_sha256': PREFLIGHT,
            'address_kind': 'virtual unless explicitly file_offset', 'file_offset': hx(off),
            'body_bytes': SIZE, 'body_sha256': sha(body), 'instruction_count': len(ins),
            'instruction_starts': [hx(i.address) for i in ins], 'all_instructions_reachable': True,
            'all_native_operands_match': True, 'calls': [], 'branches': branches,
            'returns': ['00683527', '006835a1'], 'explicit_memory_reads': reads,
            'switch_table': {'va': hx(TABLE), 'file_offset': hx(table_off), 'bytes': 20,
                'hex': table.hex(), 'sha256': sha(table), 'targets': [hx(a) for a in TARGETS],
                'outside_native_body': True, 'all_targets_inside_body': True},
            'python_optimized_integrity': 'explicit ValueError gates, no assert'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=Path)
    p.add_argument('--exports', type=Path, required=True)
    p.add_argument('--preflight', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('evidence/league-comparator-26-sites.json'))
    a = p.parse_args()
    result = extract(a.binary, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8', newline='\n')
    print('verified R26-C complete local operands and switch-table CFG:', result['instruction_count'], 'instructions')
