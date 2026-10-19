#!/usr/bin/env python3
"""Compare R30 prefix/dependency operands and CFG against private native exports."""
import argparse
import json
from pathlib import Path
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM
from emulate_action33_prefix_30 import (EXPECTED,RANGES,decode,pe_offset,need,sha,hx)

FRESH_MANIFEST='5089d7a53a599ffaeada705cc7fb02ae62ab76070e3c886ac57cd99080019a4f'
R29_MANIFEST='ced03a8f3d9da3cc61fcb9d63e0be55cb1cc39776615c038e0320836a526c0da'
R29_PREFLIGHT='cee6d3c36808bd69afb14796fa22314a8900909e3b59e08544e5bdfe58063a0c'
CALLER_HASH='40afb06c0e55a22091d0aff2bcca1521feadc9fae0bb87f9416ab4a72472f8cf'
RUNTIME_MANIFEST='4ef765c1d661f044d2c80eacdecaee7600e0d4eb8766901872c8444f6d71545c'
BODIES={0x5b57c0:15,0x6d59b0:93,0x6f09b0:61,0x700420:1919,
        0x713e90:304,0x714d30:4,0x7160f0:373,0x6ce110:500,0x6c38c0:42}


def normalized(s):
    s=s.lower().replace('float ptr','dword ptr').replace('double ptr','qword ptr')
    # Ghidra omits the default dword qualifier for some integer loads/stores.
    s=s.replace('dword ptr','')
    s=re.sub(r'st\(([0-7])\)',r'st\1',s)
    if s in ('faddp st1','fmulp st1'):s=s.split()[0]
    s=re.sub(r'0x[0-9a-f]+',lambda m:str((int(m[0],16)+0x80000000)%0x100000000-0x80000000),s)
    s=re.sub(r'\s+','',s)
    s=re.sub(r'\*1(?!\d)','',s).replace('+-','-').replace('+0]',']')
    for old,new in (('jnz','jne'),('jz','je'),('setz','sete'),('setnz','setne')):
        if s.startswith(old):s=new+s[len(old):]
    return s


def verify_manifest(folder,pinned):
    raw=(folder/'manifest.json').read_bytes()
    need(pinned is not None and sha(raw)==pinned,'native manifest digest mismatch')
    manifest=json.loads(raw)
    need(manifest['specimen_sha256']==EXPECTED,'native specimen mismatch')
    for name,meta in manifest['files'].items():
        need(Path(name).name==name,'manifest filename outside folder')
        value=(folder/name).read_bytes()
        need(len(value)==meta['bytes'] and sha(value)==meta['sha256'],'native file digest mismatch '+name)
    return manifest


def rows(path):
    return {int(m[1],16):m[2] for m in re.finditer(r'^([0-9a-fA-F]{8})\s+(.+)$',path.read_text(encoding='utf-8-sig'),re.M)}


def compare(insns,native):
    for a,i in insns.items():
        need(a in native,'native instruction absent '+hx(a))
        ours=i.mnemonic+' '+i.op_str
        need(normalized(ours)==normalized(native[a]),'native operand mismatch '+hx(a)+': '+ours+' / '+native[a])


def extract(binary,fresh,r29,preflight,caller,runtime):
    data=binary.read_bytes();admitted,ranges=decode(data)
    fm=verify_manifest(fresh,FRESH_MANIFEST);rm=verify_manifest(r29,R29_MANIFEST)
    verify_manifest(runtime,RUNTIME_MANIFEST)
    need(sha(preflight.read_bytes())==R29_PREFLIGHT,'R29 preflight mismatch')
    need(sha(caller.read_bytes())==CALLER_HASH,'caller native export mismatch')
    all_native=rows(caller);sources={'00702050':CALLER_HASH};full=[]
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    for entry,length in BODIES.items():
        folder=r29 if entry in (0x6ce110,0x6c38c0) else fresh
        path=folder/(hx(entry)+'.asm');native=rows(path);sources[hx(entry)]=sha(path.read_bytes())
        off=pe_offset(data,entry,length)
        decoded={i.address:i for i in md.disasm(data[off:off+length],entry)}
        need(sum(i.size for i in decoded.values())==length,'complete dependency decode failed')
        need(set(decoded)==set(native),'complete dependency native address set mismatch '+hx(entry))
        compare(decoded,native);all_native.update(native)
        branches=[];calls=[];returns=[];cfg=[];indirect=[]
        for a,i in decoded.items():
            if i.mnemonic.startswith('ret'):returns.append([hx(a),int(i.op_str or '0',0)]);targets=[]
            elif i.mnemonic.startswith('j'):
                if i.operands[0].type==CS_OP_IMM:
                    targets=[i.operands[0].imm]+([] if i.mnemonic=='jmp' else [a+i.size])
                    need(all(t in decoded for t in targets),'dependency CFG escape')
                    branches.append([hx(a),i.mnemonic,[hx(t) for t in targets]])
                else:
                    need(entry==0x700420,'unexpected dependency indirect branch')
                    targets=[];indirect.append(hx(a))
            else:targets=[a+i.size]
            cfg.extend([[hx(a),hx(t)] for t in targets])
            if i.mnemonic=='call':calls.append([hx(a),hx(i.operands[0].imm)])
        full.append({'entry':hx(entry),'bytes':length,'sha256':sha(data[off:off+length]),'instructions':len(decoded),
          'branches':branches,'calls':calls,'returns':returns,'direct_local_cfg_edges':len(cfg),
          'unresolved_indirect_branches_outside_admitted_action33_path':indirect,
          'local_cfg_sha256':sha(json.dumps(cfg,separators=(',',':')).encode()),'native_asm_sha256':sha(path.read_bytes())})
    for name in ('0090cfc0','00946a04','00945640'):
        path=runtime/(name+'.asm');all_native.update(rows(path));sources[name]=sha(path.read_bytes())
    # Ghidra treats 9B D9 /7 as one FSTCW. Capstone/Unicorn expose WAIT followed
    # by FNSTCW. Verify the exact combined native operand before splitting it.
    need(normalized(all_native[0x945646])==normalized('fstcw word ptr [ebp-2]') and 0x945647 not in all_native,
         'native WAIT/FNSTCW fusion changed')
    all_native[0x945646]='wait';all_native[0x945647]='fnstcw word ptr [ebp-2]'
    compare(admitted,all_native)
    calls=[];branches=[];exits=[]
    for a,i in admitted.items():
        if i.mnemonic=='call':calls.append([hx(a),hx(i.operands[0].imm)])
        if i.mnemonic.startswith('j'):
            if i.operands[0].type==CS_OP_IMM:
                targets=[i.operands[0].imm]+([] if i.mnemonic=='jmp' else [a+i.size])
                branches.append([hx(a),i.mnemonic,[hx(t) for t in targets]])
                exits.extend([[hx(a),hx(t)] for t in targets if t not in admitted])
            else:
                need(a==0x7023a6,'unexpected indirect branch')
                # Exact action33 byte-table lookup and destination-table entry.
                ix=data[pe_offset(data,0x70a5a8+0x33-0x16,1)]
                dest=int.from_bytes(data[pe_offset(data,0x70a594+4*ix,4):pe_offset(data,0x70a594+4*ix,4)+4],'little')
                need(ix==4 and dest==0x7023e1,'action33 switch changed')
                branches.append([hx(a),'action33 indirect',[hx(dest)]])
    return {'unit':'R30-A','specimen_sha256':EXPECTED,'address_kind':'virtual; file offsets separately labelled',
      'fresh_manifest_sha256':FRESH_MANIFEST,'r29_manifest_sha256':R29_MANIFEST,'r29_preflight_sha256':R29_PREFLIGHT,
      'runtime_manifest_sha256':RUNTIME_MANIFEST,'source_assembly_sha256':sources,
      'admitted_instruction_count':len(admitted),'all_admitted_native_operands_match':True,
      'decoder_boundary_normalization':'Ghidra FSTCW at 00945646 expands to Capstone WAIT 00945646 / FNSTCW word[EBP-2] 00945647',
      'admitted_ranges':ranges,'complete_local_dependency_comparisons':full,
      'calls_in_admitted_ranges':calls,'branch_edges_in_admitted_ranges':branches,'unadmitted_edges':exits,
      'scope':'static prefix and dependency integrity; generic unadmitted edges remain excluded, no complete resolver contract',
      'first_guarded_dependency':{'caller':'0070210b','entry':'006d59b0','scan_call':'006d59f0','target':'007160f0',
         'getter_call':'0071611c','getter':'005b57c0','guard':'TEST AL,04; JE 00716194',
         'first_unadmitted_instruction_if_set':'00716125','next_transitive_call':'0071614b -> 005b58e0'}}


def parser():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path)
    for name in ('fresh','r29','preflight','caller','runtime','output'):p.add_argument('--'+name,type=Path,required=True)
    return p


if __name__=='__main__':
    a=parser().parse_args();result=extract(a.binary,a.fresh,a.r29,a.preflight,a.caller,a.runtime)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(result['admitted_instruction_count'],'original/native instruction operands match')
