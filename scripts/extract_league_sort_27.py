#!/usr/bin/env python3
"""Verify R27-C league caller and CRT sort local bodies against PE/native exports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST = 'bbd00280029a738f4f4dfa6462c7d34a4379887626749d9f20eef20873655f14'
PREFLIGHT = 'fb1be5075c72e92045f4d802f649665801d8ebc85b049a25e0f652e282f6015d'
CHECKPOINT = '4acf11ca1ab79b275436c6365813904d87634436de1723ce24a2274f83a087c4'
BODIES = {0x682b30: 730, 0x945333: 340}
EXPECTED_NAMES = {0x682b30: 'cm0102_write_league_peer_bucket_bytes_candidate', 0x945333: 'FUN_00945333'}
CALLS = {0x682b30: {0x5e8290, 0x6834f0, 0x90d130, 0x944c9f, 0x944cff, 0x9452ca, 0x945333, 0x945501},
         0x945333: {0x945487, 0x9454d5}}
INDIRECT = {0x945333: {0x9453d8, 0x9453ea}, 0x682b30: set()}
HELPERS = {0x945487: (78, 'e9602fb435ba6e492a49997a9809e95763bc31dcb8f36acdd7a1bdd6620b72de'),
           0x9454d5: (44, '8cc073e4161c512ba0dc2a7bb381d401f4f08e67cba8d2176b495fd552a36df1')}
SELECTED = {0x682b3c, 0x682b45, 0x682bc1, 0x682d1a, 0x682d1e, 0x682d23, 0x682d25,
            0x682d26, 0x682d27, 0x682d2c, 0x682dd2, 0x682df5, 0x682e07,
            0x94533e, 0x945342, 0x94534b, 0x945355, 0x945359, 0x94535a, 0x945367,
            0x945372, 0x94537b, 0x945383, 0x945389, 0x945391, 0x945394, 0x945398,
            0x9453b2, 0x9453bc, 0x9453d8, 0x9453ea, 0x9453ff, 0x94540a, 0x94543f,
            0x945441, 0x945460, 0x945469, 0x945482, 0x945486}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(n):
    return f'{n:08x}'


def normalized(s):
    s = s.lower().strip().replace('float ptr', 'dword ptr').replace('double ptr', 'qword ptr')
    s = re.sub(r'0x[0-9a-f]+', lambda m: str((int(m[0], 16)+0x80000000)%0x100000000-0x80000000), s)
    s = re.sub(r'\s+', '', s).replace('*0x1', '').replace('*1', '').replace('+-', '-').replace('+0]', ']')
    for a, b in [('jz', 'je'), ('jnz', 'jne'), ('jc', 'jb'), ('jnc', 'jae')]:
        if s.startswith(a):
            s = b+s[len(a):]
    return s


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
    need(sha(manifest_raw) == MANIFEST and sha(old_raw) == PREFLIGHT, 'manifest/preflight SHA-256 mismatch')
    manifest, old = json.loads(manifest_raw), json.loads(old_raw)
    need(manifest['specimen_sha256'] == old['sha256'] == SPECIMEN and
         manifest['checkpoint_archive_sha256'] == CHECKPOINT and
         manifest['preflight_sha256'] == PREFLIGHT, 'native provenance mismatch')
    need(set(manifest['files']) == {hx(a)+ext for a in [0x682b30,0x68d1b0,0x68d1d0,0x68d1f0,0x945333,0x9488e0]
                                  for ext in ['.asm','.c']}, 'native export inventory mismatch')
    for name, meta in manifest['files'].items():
        raw = (exports/name).read_bytes()
        need(len(raw) == meta['bytes'] and sha(raw) == meta['sha256'], 'native export mismatch: '+name)
    old_sites = {int(s['address'],16):s for s in old['sites']}
    need(len(old_sites) == 5, 'preflight site inventory mismatch')
    result = {}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    for entry, size in BODIES.items():
        name = hx(entry)
        site = old_sites[entry]
        need(site['function_name'] == EXPECTED_NAMES[entry] and
             site['instruction_exists'] is True and site['body_addresses'] == size,
             'exact-old native name/body mismatch: '+name)
        off = pe_offset(pe, entry, size)
        body = pe[off:off+size]
        ins = list(md.disasm(body, entry))
        need(ins and sum(i.size for i in ins) == size and ins[-1].address+ins[-1].size == entry+size,
             'incomplete body decode: '+name)
        native = [(int(m[1],16),m[2]) for m in re.finditer(r'^([0-9a-fA-F]{8})\s+(.+)$',
                  (exports/(name+'.asm')).read_text(encoding='utf-8-sig'), re.M)]
        need(len(native) == len(ins), 'native instruction count mismatch: '+name)
        starts = {i.address for i in ins}
        for i,(address,line) in zip(ins,native):
            need(i.address == address and normalized(i.mnemonic+' '+i.op_str) == normalized(line),
                 'PE/native opcode or operand mismatch at '+hx(i.address)+': '+i.mnemonic+' '+i.op_str+' / '+line)
        edges, branches, calls, indirect, reads, writes = {}, [], [], [], [], []
        for i in ins:
            fall = i.address+i.size
            if i.mnemonic == 'ret':
                targets = []
            elif i.mnemonic.startswith('j'):
                need(len(i.operands)==1 and i.operands[0].type==capstone.x86.X86_OP_IMM,
                     'indirect branch at '+hx(i.address))
                targets = [i.operands[0].imm]+([] if i.mnemonic=='jmp' else [fall])
                branches.append([hx(i.address),i.mnemonic,[hx(a) for a in targets]])
            else:
                targets = [fall]
            need(all(a in starts for a in targets), 'CFG escapes body at '+hx(i.address))
            edges[i.address] = targets
            if i.mnemonic == 'call':
                op = i.operands[0]
                if op.type == capstone.x86.X86_OP_IMM:
                    calls.append([hx(i.address),hx(op.imm)])
                else:
                    need(op.type == capstone.x86.X86_OP_MEM and op.size == 4,
                         'unexpected indirect call form at '+hx(i.address))
                    indirect.append([hx(i.address),i.op_str])
            for op in i.operands:
                if op.type != capstone.x86.X86_OP_MEM or i.mnemonic == 'lea':
                    continue
                row = [hx(i.address),op.size,i.op_str]
                if op.access & capstone.CS_AC_READ:
                    reads.append(row)
                if op.access & capstone.CS_AC_WRITE:
                    writes.append(row)
        need({int(target,16) for _,target in calls} == CALLS[entry], 'direct call set changed: '+name)
        need({int(addr,16) for addr,_ in indirect} == INDIRECT[entry], 'indirect callback set changed: '+name)
        reached, pending = set(), [entry]
        while pending:
            a = pending.pop()
            if a not in reached:
                reached.add(a)
                pending.extend(edges[a])
        need(reached == starts, 'unreachable local instruction: '+name)
        result[name] = {
            'entry_va': name, 'file_offset': hx(off), 'body_bytes': size, 'body_sha256': sha(body),
            'old_native_name': EXPECTED_NAMES[entry], 'instruction_count': len(ins),
            'all_native_operands_match': True, 'all_instructions_reachable': True,
            'instruction_starts_sha256': sha(('\n'.join(hx(i.address) for i in ins)+'\n').encode()),
            'local_edge_count': sum(len(v) for v in edges.values()), 'branches': branches,
            'direct_calls': calls, 'indirect_calls': indirect,
            'returns': [[hx(i.address),int(i.op_str or '0',0)] for i in ins if i.mnemonic=='ret'],
            'explicit_memory_reads': reads, 'explicit_memory_writes': writes,
            'selected_instructions': {hx(i.address):i.mnemonic+' '+i.op_str for i in ins if i.address in SELECTED},
            'native_export_hashes': {ext:manifest['files'][name+'.'+ext]['sha256'] for ext in ('asm','c')}
        }
    helpers = {}
    for va,(length,digest) in HELPERS.items():
        off = pe_offset(pe,va,length)
        need(sha(pe[off:off+length]) == digest, 'read-only helper dependency bytes changed: '+hx(va))
        helpers[hx(va)] = {'file_offset':hx(off),'body_bytes':length,'body_sha256':digest,
                           'scope':'read-only dependency; no native export or complete R27-C contract'}
    return {'schema_version':1, 'unit':'R27-C', 'address_kind':'virtual unless file_offset is explicit',
            'specimen_sha256':SPECIMEN, 'checkpoint_archive_sha256':CHECKPOINT,
            'export_manifest_sha256':MANIFEST, 'annotation_preflight_sha256':PREFLIGHT,
            'scope':'complete local PE/native bodies; called helpers and callbacks are separate boundaries',
            'python_optimized_integrity':'explicit ValueError gates, no assert',
            'read_only_helper_spans':helpers, 'bodies':result}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path)
    p.add_argument('--exports',type=Path,required=True)
    p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    result = extract(a.binary,a.exports,a.preflight)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('verified R27-C PE/native bodies:', [(k,v['instruction_count']) for k,v in result['bodies'].items()])
