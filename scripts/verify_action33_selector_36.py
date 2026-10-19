#!/usr/bin/env python3
"""R36-A normal/optimized reproduction, payload/privacy limits and mutations."""
import argparse
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zlib

import emulate_action33_selector_36 as task
from verify_action33_adjustment_34 import BytesFile, reject, scan
from verify_action33_rng_35 import snapshot
from emulate_action33_prefix_30 import need, sha, compact, packed, pe_offset
from extract_action33_prefix_30 import rows, compare

ORACLE='f019948252ce992d2fd43d5ddf9a51b0646c3fb8fe1837ca4ef009f4dd63d3ce'


def expand(blob):
    need(len(blob)<1000000 and blob[:10]==bytes.fromhex('1f8b08000000000002ff'),'noncanonical gzip envelope')
    stream=zlib.decompressobj(31);raw=stream.decompress(blob,12000001)
    need(len(raw)<=12000000 and not stream.unconsumed_tail,'oversized public payload')
    need(stream.eof and not stream.unused_data,'incomplete public payload')
    return raw


def public_payload(blob):
    raw=expand(blob);value=json.loads(raw)
    need(raw==compact(value)+b'\n' and blob==packed(value),'noncanonical public payload')
    need(set(value)=={'unit','sites','cases','scope','coverage'} and value['unit']=='R36-A','public shape changed')
    need(len(value['cases'])==len(task.schedule())==232,'case count changed')
    need(value['sites']['next_calls']=={'00702332':'00944cff','007023e3':'0090cfc0'},'next boundaries changed')
    need(value['sites']['dependency_hashes']==task.DEPENDENCIES,'dependency hashes changed')
    for n,row in enumerate(value['cases']):
        need(set(row)=={'id','case','before','checkpoint','after','stop','boundary','selected','calls','rng','events',
          'instruction_trace','suffix_state_sha256','suffix_states','selector_events','r30c_selector_projection','memory_sha256'},'case shape changed')
        need(row['id']==n and row['case']==task.schedule()[n] and int(row['stop'],16) in task.STOPS,'schedule or stop changed')
        for state in (row['before'],row['after'],row['checkpoint']['state']):snapshot(state)
        need(row['before']['rng']==row['after']['rng'] and row['before']['rng_cells']==row['after']['rng_cells'],'RNG advanced')
        need(len(row['rng'])==1 and row['rng'][0]['site']=='00702241' and row['rng'][0]['arguments']==[0],'RNG call changed')
        need(row['suffix_states']==len(row['instruction_trace'])-row['checkpoint']['trace_length'],'suffix count changed')
        digest=row['suffix_state_sha256'];need(len(digest)==64 and set(digest)<=set('0123456789abcdef'),'invalid state digest')
        need((row['selected']==0)==(row['stop']=='00702332'),'null branch changed')
        for call in row['calls']:
            need(set(call)=={'site','target','before','after','arguments'},'call shape changed');snapshot(call['before']);snapshot(call['after'])
        for digests,regions in ((row['memory_sha256'],task.REGIONS),(row['checkpoint']['memory_sha256'],task.prior.REGIONS)):
            need(set(digests)==set(regions),'region shape changed')
            need(all(len(v)==64 and set(v)<=set('0123456789abcdef') for v in digests.values()),'invalid region hash')
        for pc,operation,address,width,operand in row['events']:
            need(operation in ('read','write') and width in (1,2,4,8),'event width/kind changed')
            numeric=int(address,16)
            need(any(base<=numeric and numeric+width<=base+length for base,length in task.REGIONS.values()),'unadmitted operand region')
            if width==8:need(type(operand)==str and len(operand)==16 and set(operand)<=set('0123456789abcdef'),'qword payload changed')
            else:need(type(operand)==int and 0<=operand<1<<(width*8),'operand payload changed')
    need(sha(blob)==ORACLE,'oracle digest mismatch')
    return value


def private_fragments(data):
    result=[]
    for start,end in task.RANGES:
        off=pe_offset(data,start,end-start);body=data[off:off+end-start];size=min(32,len(body))
        if size<12:continue
        for n in range(0,len(body)-size+1,16):
            sample=body[n:n+size]
            if len(set(sample))>5:result.append(sample)
    need(bool(result),'missing privacy samples');return result


def verify(a):
    root=Path(__file__).resolve().parents[1];retained=(root/'evidence/action33-selector-36-oracle.bin').read_bytes()
    oracle=public_payload(retained);failures={};(root/'results').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='selector-36-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            subprocess.run([sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_selector_36.py'),str(a.binary),
              '--fresh',str(a.fresh),'--caller',str(a.caller),'--runtime',str(a.runtime),'--r29',str(a.r29),'--output',str(output)],check=True,capture_output=True)
            need(output.read_bytes()==retained,'normal/-O regeneration changed')
        data,ins,_=task.extract(a)
        changed=bytearray(data);changed[pe_offset(data,0x6ce2f8,1)]^=1
        mutated=argparse.Namespace(**{**vars(a),'binary':BytesFile(changed)})
        failures['changed_PE']=reject(lambda:task.extract(mutated),'specimen SHA-256/size mismatch')
        selector={address:instruction for address,instruction in ins.items() if task.SELECTOR<=address<0x6ce304}
        native=rows(a.r29/'006ce110.asm');native[0x6ce2e6]='MOV AL,byte ptr [ESP + 0x10]'
        failures['native_selector_operand']=reject(lambda:compare(selector,native),'native operand mismatch 006ce2e6')
        altered=folder/'native';shutil.copytree(a.r29,altered)
        path=altered/'006ce110.asm';path.write_bytes(path.read_bytes()+b'\n')
        changed_args=argparse.Namespace(**{**vars(a),'r29':altered})
        failures['changed_native_selector']=reject(lambda:task.extract(changed_args),'native file digest mismatch 006ce110.asm')
        table=bytearray((root/'evidence/random-validation/random-table.bin').read_bytes());table[0]^=1
        failures['changed_synthetic_table']=reject(lambda:task.prior.validate_table(table),'synthetic random table mismatch')
        old_schedule=task.schedule;task.schedule=lambda:[old_schedule()[0]]
        try:
            failures['actual_preserved_register']=reject(lambda:task.generate(a,'return-esi'),'selector preserved register changed esi')
            failures['actual_return_cleanup']=reject(lambda:task.generate(a,'return-esp'),'selector RET 4 ABI mismatch')
            failures['actual_rng_cell']=reject(lambda:task.generate(a,'rng-cell'),'selector advanced RNG')
            failures['unsupported_reserve_branch']=reject(lambda:task.generate(a,'reserve'),'unsupported reserve branch 006ce17e')
            failures['actual_dispatch_byte']=reject(lambda:task.generate(a,'dispatch'),'unadmitted data access 0070a5a0')
        finally:task.schedule=old_schedule
        wrong=gzip.compress(expand(retained)+b' ',compresslevel=9,mtime=0);wrong=wrong[:9]+b'\xff'+wrong[10:]
        failures['appended_json_whitespace']=reject(lambda:public_payload(wrong),'noncanonical public payload')
        failures['alternate_gzip_envelope']=reject(lambda:public_payload(retained[:9]+b'\x03'+retained[10:]),'noncanonical gzip envelope')
        failures['oversized_expansion']=reject(lambda:expand(packed('x'*12000001)),'oversized public payload')
        changed=json.loads(expand(retained));changed['cases'][0]['suffix_state_sha256']='0'*64
        failures['changed_state_digest']=reject(lambda:public_payload(packed(changed)),'oracle digest mismatch')
        fragments=private_fragments(data)
        for path in (*root.glob('scripts/*action33_selector_36.py'),*root.glob('reconstruction/*action33-selector-36.ts'),
                     *root.glob('reports/*action33-selector-36.md'),*root.glob('evidence/*action33-selector-36*')):
            raw=path.read_bytes();scan(raw,fragments)
            if path.suffix=='.bin':scan(expand(raw),fragments)
        failures['private_raw_fragment']=reject(lambda:scan(b'x'+fragments[0]+b'y',fragments),'private original fragment')
        failures['private_hex_fragment']=reject(lambda:scan(fragments[0].hex().upper().encode(),fragments),'private original fragment')
        failures['compressed_private_fragment']=reject(lambda:scan(expand(packed({'probe':fragments[-1].hex()})),fragments),'private original fragment')
    return {'unit':'R36-A','status':'passed','oracle_sha256':sha(retained),'specimen_sha256':task.p.EXPECTED,
      'coverage':oracle['coverage'],'normal_optimized':'byte-identical original instruction regeneration',
      'negative_checks':failures,'privacy':'bounded canonical gzip, fixed synthetic schedule and raw/hex/expanded original-code scans',
      'scope':'original-entry selector and caller to pre-variant RNG or null diagnostic; reserve branches and full R30-C state join remain open'}


if __name__=='__main__':
    args=task.parser().parse_args();result=verify(args);args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(result['status'],len(result['negative_checks']))
