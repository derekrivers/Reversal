#!/usr/bin/env python3
"""Pin and compare every R28-A instruction against the saved native exports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST = '058514c602952b66abeade64ba9a28bbab3873c16503af4ca0f834fb2a6d2ddc'
PREFLIGHT = '9f9e52088fc32356aebecb6fc39ba78fea96e14f359383afb01362287409fbb2'
CHECKPOINT = 'd2836fd1b28d194dbfda32454106f9af23495809f09a408ed1ee072e6c4b7de1'
BODIES = {0x945487: 78, 0x9454d5: 44}

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
    need(set(manifest['files'])=={f'{a:08x}{ext}' for a in [0x68cfc0,0x68d020,0x68d0d0,0x944cf1,0x944e58,0x945487,0x9454d5] for ext in ('.asm','.c')},
         'native export inventory mismatch')
    for name,meta in manifest['files'].items():
        raw=(exports/name).read_bytes()
        need(len(raw)==meta['bytes'] and sha(raw)==meta['sha256'], 'native export mismatch: '+name)
    sites={int(row['address'],16):row for row in old['sites']}
    need(set(sites)=={0x68cfc0,0x68d020,0x68d0d0,0x944cf1,0x944e58,0x945487,0x9454d5},'old site inventory mismatch')
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    md.detail=True
    result=[]
    for entry,size in BODIES.items():
        name=hx(entry); site=sites[entry]
        need(site['function_name']=='FUN_'+name and site['instruction_exists'] is True and site['body_addresses']==size,
             'exact-old site mismatch: '+name)
        off=pe_offset(pe,entry,size); body=pe[off:off+size]
        ins=list(md.disasm(body,entry)); starts={i.address for i in ins}
        need(ins and sum(i.size for i in ins)==size and ins[-1].address+ins[-1].size==entry+size,'incomplete decode: '+name)
        native=[(int(m[1],16),m[2]) for m in re.finditer(r'^([0-9a-fA-F]{8})\s+(.+)$',
                (exports/(name+'.asm')).read_text(encoding='utf-8-sig'),re.M)]
        need(len(native)==len(ins),'native instruction count mismatch: '+name)
        for i,(addr,line) in zip(ins,native):
            need(i.address==addr and norm(i.mnemonic+' '+i.op_str)==norm(line),
                 f'PE/native opcode/operand mismatch at {hx(i.address)}: {i.mnemonic} {i.op_str} / {line}')
        edges=[]; branches=[]; calls=[]; indirect=[]; reads=[]; writes=[]
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
            if i.mnemonic=='call':
                op=i.operands[0]
                if op.type==capstone.x86.X86_OP_IMM: calls.append([hx(i.address),hx(op.imm)])
                else:
                    need(op.type==capstone.x86.X86_OP_MEM and op.size==4,'unexpected callback operand')
                    indirect.append([hx(i.address),i.op_str])
            for op in i.operands:
                if op.type!=capstone.x86.X86_OP_MEM or i.mnemonic=='lea': continue
                row=[hx(i.address),op.size,i.op_str]
                if op.access & capstone.CS_AC_READ: reads.append(row)
                if op.access & capstone.CS_AC_WRITE: writes.append(row)
        graph={a:[] for a in starts}
        for a,b in edges: graph[int(a,16)].append(int(b,16))
        reached=set(); todo=[entry]
        while todo:
            a=todo.pop()
            if a not in reached: reached.add(a);todo.extend(graph[a])
        need(reached==starts,'unreachable local instructions: '+name)
        need(calls==([['009454c0','009454d5']] if entry==0x945487 else []) and
             indirect==([['009454ab','dword ptr [ebp + 0x14]']] if entry==0x945487 else []),
             'call boundary mismatch: '+name)
        result.append({'entry_va':name,'file_offset':hx(off),'body_bytes':size,'body_sha256':sha(body),
                       'old_native_name':site['function_name'],'instruction_count':len(ins),
                       'matched_native_instructions':len(native),'instruction_starts':[hx(i.address) for i in ins],
                       'local_edge_count':len(edges),'edges':edges,'branches':branches,
                       'direct_calls':calls,'indirect_calls':indirect,'returns':[hx(i.address) for i in ins if i.mnemonic=='ret'],
                       'explicit_memory_reads':reads,'explicit_memory_writes':writes,
                       'native_export_hashes':{ext:manifest['files'][name+'.'+ext]['sha256'] for ext in ('asm','c')}})
    return {'schema_version':1,'unit':'R28-A','address_kind':'virtual unless file_offset specified',
            'specimen_sha256':SPECIMEN,'checkpoint_archive_sha256':CHECKPOINT,
            'export_manifest_sha256':MANIFEST,'annotation_preflight_sha256':PREFLIGHT,
            'python_optimized_integrity':'explicit ValueError gates; no assert', 'functions':result}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path);p.add_argument('--exports',type=Path,required=True)
    p.add_argument('--preflight',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();result=extract(a.binary,a.exports,a.preflight)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print([(f['entry_va'],f['instruction_count'],f['local_edge_count']) for f in result['functions']])
