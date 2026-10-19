#!/usr/bin/env python3
"""Verify the complete R29-A PE body against the read-only native export."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST = 'ced03a8f3d9da3cc61fcb9d63e0be55cb1cc39776615c038e0320836a526c0da'
PREFLIGHT = 'cee6d3c36808bd69afb14796fa22314a8900909e3b59e08544e5bdfe58063a0c'
CHECKPOINT = 'ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a'
ENTRY, SIZE = 0x6ce110, 500

def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def hx(value):
    return f'{value:08x}'

def norm(value):
    value = value.lower().strip()
    value = re.sub(r'0x[0-9a-f]+', lambda m: str((int(m[0],16)+0x80000000)%0x100000000-0x80000000), value)
    value = re.sub(r'\s+', '', value).replace('*0x1', '').replace('*1', '').replace('+-', '-').replace('+0]', ']')
    for old,new in [('jz','je'),('jnz','jne'),('jc','jb'),('jnc','jae')]:
        if value.startswith(old):
            value = new+value[len(old):]
    return value

def pe_offset(pe, va, size):
    header = struct.unpack_from('<I', pe, 0x3c)[0]
    need(pe[:2] == b'MZ' and pe[header:header+4] == b'PE\0\0', 'invalid PE')
    need(struct.unpack_from('<H',pe,header+4)[0] == 0x14c and struct.unpack_from('<H',pe,header+24)[0] == 0x10b, 'requires PE32 x86')
    count, opt_size = struct.unpack_from('<H',pe,header+6)[0], struct.unpack_from('<H',pe,header+20)[0]
    base = struct.unpack_from('<I',pe,header+24+28)[0]
    matches = []
    for i in range(count):
        _, virtual, rva, raw, off = struct.unpack_from('<8sIIII',pe,header+24+opt_size+40*i)
        delta = va-base-rva
        if 0 <= delta and delta+size <= min(virtual,raw):
            matches.append(off+delta)
    need(len(matches)==1, 'range not uniquely raw-backed')
    return matches[0]

def extract(binary, exports, preflight):
    need(capstone.__version__ == '5.0.7', 'requires Capstone 5.0.7')
    pe = binary.read_bytes()
    need(len(pe)==7192576 and sha(pe)==SPECIMEN, 'specimen mismatch')
    manifest_raw, old_raw = (exports/'manifest.json').read_bytes(), preflight.read_bytes()
    need(sha(manifest_raw)==MANIFEST and sha(old_raw)==PREFLIGHT, 'native provenance hash mismatch')
    manifest, old = json.loads(manifest_raw), json.loads(old_raw)
    need(manifest['specimen_sha256']==old['sha256']==SPECIMEN and
         manifest['checkpoint_archive_sha256']==CHECKPOINT and manifest['preflight_sha256']==PREFLIGHT,
         'native provenance mismatch')
    need('006ce110.asm' in manifest['files'] and '006ce110.c' in manifest['files'], 'native inventory missing target')
    for name,meta in manifest['files'].items():
        raw=(exports/name).read_bytes()
        need(len(raw)==meta['bytes'] and sha(raw)==meta['sha256'], 'native export mismatch: '+name)
    sites={int(row['address'],16):row for row in old['sites']}
    site=sites[ENTRY]
    need(site['function_name']=='cm0102_select_goalkeeper_slot_candidate' and site['instruction_exists'] is True and
         site['body_addresses']==SIZE and 'Investigation09 static refinement' in site['function_comment'], 'exact-old annotation mismatch')
    off=pe_offset(pe,ENTRY,SIZE); body=pe[off:off+SIZE]
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ins=list(md.disasm(body,ENTRY));starts={i.address for i in ins}
    need(ins and sum(i.size for i in ins)==SIZE and ins[-1].address+ins[-1].size==ENTRY+SIZE,'incomplete decode')
    native=[(int(m[1],16),m[2]) for m in re.finditer(r'^([0-9a-fA-F]{8})\s+(.+)$',
            (exports/'006ce110.asm').read_text(encoding='utf-8-sig'),re.M)]
    need(len(native)==len(ins),'native instruction count mismatch')
    for i,(addr,line) in zip(ins,native):
        need(i.address==addr and norm(i.mnemonic+' '+i.op_str)==norm(line),
             f'PE/native opcode/operand mismatch at {hx(i.address)}: {i.mnemonic} {i.op_str} / {line}')
    edges=[];branches=[];reads=[];writes=[];calls=[]
    for i in ins:
        fall=i.address+i.size
        if i.mnemonic=='ret': targets=[]
        elif i.mnemonic.startswith('j'):
            need(len(i.operands)==1 and i.operands[0].type==capstone.x86.X86_OP_IMM,'indirect branch')
            targets=[i.operands[0].imm]+([] if i.mnemonic=='jmp' else [fall])
            branches.append([hx(i.address),i.mnemonic,[hx(t) for t in targets]])
        else: targets=[fall]
        need(all(t in starts for t in targets),'CFG escapes body at '+hx(i.address))
        edges += [[hx(i.address),hx(t)] for t in targets]
        if i.mnemonic=='call': calls.append(hx(i.address))
        for op in i.operands:
            if op.type!=capstone.x86.X86_OP_MEM or i.mnemonic=='lea': continue
            row=[hx(i.address),op.size,i.op_str]
            if op.access & capstone.CS_AC_READ: reads.append(row)
            if op.access & capstone.CS_AC_WRITE: writes.append(row)
    need(not calls,'unexpected callee')
    graph={a:[] for a in starts}
    for a,b in edges:graph[int(a,16)].append(int(b,16))
    reached=set();todo=[ENTRY]
    while todo:
        a=todo.pop()
        if a not in reached:reached.add(a);todo.extend(graph[a])
    need(reached==starts,'unreachable local instructions')
    return {'schema_version':1,'unit':'R29-A','address_kind':'virtual unless file_offset specified',
            'specimen_sha256':SPECIMEN,'checkpoint_archive_sha256':CHECKPOINT,
            'export_manifest_sha256':MANIFEST,'annotation_preflight_sha256':PREFLIGHT,
            'entry_va':hx(ENTRY),'file_offset':hx(off),'body_bytes':SIZE,'body_sha256':sha(body),
            'old_native_name':site['function_name'],'instruction_count':len(ins),'matched_native_instructions':len(native),
            'instruction_starts':[hx(i.address) for i in ins], 'local_edge_count':len(edges), 'edges':edges,
            'branches':branches,'returns':[hx(i.address) for i in ins if i.mnemonic=='ret'],
            'direct_calls':calls,'explicit_memory_reads':reads,'explicit_memory_writes':writes,
            'native_export_hashes':{ext:manifest['files']['006ce110.'+ext]['sha256'] for ext in ('asm','c')},
            'python_optimized_integrity':'explicit ValueError gates; no assert'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path)
    p.add_argument('--exports',type=Path,required=True);p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=extract(a.binary,a.exports,a.preflight)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(result['instruction_count'],result['local_edge_count'],result['body_sha256'])
