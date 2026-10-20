#!/usr/bin/env python3
"""R37-B normal/optimized reproduction, payload/privacy limits and mutations."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zlib

import emulate_action33_variant_37 as task
from verify_action33_adjustment_34 import BytesFile, reject
from verify_action33_rng_35 import snapshot
from emulate_action33_prefix_30 import need, sha, compact, packed, pe_offset
from extract_action33_prefix_30 import rows, compare

ORACLE='e78aa4f325e9737245ea35b6078c113b9b60a599b2e0eace2c1738bd6160bf59'


def expand(blob):
    need(len(blob)<1200000 and blob[:10]==bytes.fromhex('1f8b08000000000002ff'),'noncanonical gzip envelope')
    stream=zlib.decompressobj(31);raw=stream.decompress(blob,16000001)
    need(len(raw)<=16000000 and not stream.unconsumed_tail,'oversized public payload')
    need(stream.eof and not stream.unused_data,'incomplete public payload')
    return raw


def public_payload(blob):
    raw=expand(blob);value=json.loads(raw)
    need(raw==compact(value)+b'\n' and blob==packed(value),'noncanonical public payload')
    need(set(value)=={'unit','sites','cases','scope','coverage'} and value['unit']=='R37-B','public shape changed')
    need(len(value['cases'])==len(task.schedule())==232,'case count changed')
    need(value['sites']['next_calls']=={'00702332':'00944cff','00702416':'00700420'},'next boundaries changed')
    need(value['sites']['dependency_hashes']==task.DEPENDENCIES,'dependency hashes changed')
    for n,row in enumerate(value['cases']):
        need(set(row)=={'id','case','before','checkpoint','after','stop','boundary','selected','calls','rng','events',
          'instruction_trace','suffix_state_sha256','suffix_states','r30c_variant_projection','memory_sha256'},'case shape changed')
        need(row['id']==n and row['case']==task.schedule()[n] and int(row['stop'],16) in task.STOPS,'schedule or stop changed')
        for state in (row['before'],row['after'],row['checkpoint']['state']):snapshot(state)
        need(row['rng'][0]['site']=='00702241' and row['rng'][0]['arguments']==[0],'initial RNG call changed')
        need(len(row['rng'])==(2 if row['selected'] else 1),'RNG call count changed')
        if row['selected']:need(row['rng'][1]['site']=='007023e3' and row['rng'][1]['arguments']==[2],'variant call changed')
        else:need(row['before']['rng']==row['after']['rng'],'diagnostic consumed RNG')
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
    result=set()
    for start,end in task.RANGES:
        off=pe_offset(data,start,end-start);body=data[off:off+end-start];size=min(32,len(body))
        if size<12:continue
        for n in range(len(body)-size+1):result.add(body[n:n+size])
        # Thirty bytes encode without padding, including when a longer
        # excerpt starts at a different base64 group alignment.
        width=min(30,len(body));width-=width%3
        for n in range(len(body)-width+1):result.add(body[n:n+width])
    need(bool(result),'missing privacy samples');return sorted(result)


def scan(payload,fragments):
    lower=payload.lower()
    for fragment in fragments:
        need(fragment not in payload and fragment.hex().encode() not in lower and
             base64.b64encode(fragment) not in payload,'private original fragment')


def verify(a):
    root=Path(__file__).resolve().parents[1];retained=(root/'evidence/action33-variant-37-oracle.bin').read_bytes()
    oracle=public_payload(retained);failures={};(root/'results').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='variant-37-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            subprocess.run([sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_variant_37.py'),str(a.binary),
              '--fresh',str(a.fresh),'--caller',str(a.caller),'--runtime',str(a.runtime),'--r29',str(a.r29),'--output',str(output)],check=True,capture_output=True)
            need(output.read_bytes()==retained,'normal/-O regeneration changed')
        data,ins,_=task.extract(a)
        changed=bytearray(data);changed[pe_offset(data,0x6ce2f8,1)]^=1
        mutated=argparse.Namespace(**{**vars(a),'binary':BytesFile(changed)})
        failures['changed_PE']=reject(lambda:task.extract(mutated),'specimen SHA-256/size mismatch')
        rng={address:instruction for address,instruction in ins.items() if 0x90cfc0<=address<0x90d02d}
        native=rows(a.runtime/'0090cfc0.asm');native[0x90cfc2]='MOV ESI,dword ptr [ESP + 0x8]'
        failures['native_rng_operand']=reject(lambda:compare(rng,native),'native operand mismatch 0090cfc2')
        altered=folder/'native';shutil.copytree(a.runtime,altered)
        path=altered/'00946a04.asm';path.write_bytes(path.read_bytes()+b'\n')
        changed_args=argparse.Namespace(**{**vars(a),'runtime':altered})
        failures['changed_native_crt']=reject(lambda:task.extract(changed_args),'native file digest mismatch 00946a04.asm')
        table=bytearray((root/'evidence/random-validation/random-table.bin').read_bytes());table[0]^=1
        failures['changed_synthetic_table']=reject(lambda:task.prior.prior.validate_table(table),'synthetic random table mismatch')
        old_schedule=task.schedule;task.schedule=lambda:[old_schedule()[0]]
        try:
            failures['actual_preserved_register']=reject(lambda:task.generate(a,'return-esi'),'variant preserved register changed esi')
            failures['actual_return_cleanup']=reject(lambda:task.generate(a,'return-esp'),'variant plain RET ABI mismatch')
            failures['actual_rng_cell']=reject(lambda:task.generate(a,'rng-cell'),'variant RNG state mismatch')
            failures['actual_crt_seed']=reject(lambda:task.generate(a,'crt-seed'),'variant RNG state mismatch')
            failures['actual_return_value']=reject(lambda:task.generate(a,'return-value'),'variant return value mismatch')
            failures['actual_caller_marker']=reject(lambda:task.generate(a,'caller-marker'),'caller variant marker mismatch')
            failures['unsupported_bound']=reject(lambda:task.generate(a,'bound'),'variant bound must be 2')
        finally:task.schedule=old_schedule
        wrong=gzip.compress(expand(retained)+b' ',compresslevel=9,mtime=0);wrong=wrong[:9]+b'\xff'+wrong[10:]
        failures['appended_json_whitespace']=reject(lambda:public_payload(wrong),'noncanonical public payload')
        failures['alternate_gzip_envelope']=reject(lambda:public_payload(retained[:9]+b'\x03'+retained[10:]),'noncanonical gzip envelope')
        failures['oversized_expansion']=reject(lambda:expand(packed('x'*16000001)),'oversized public payload')
        changed=json.loads(expand(retained));changed['cases'][0]['suffix_state_sha256']='0'*64
        failures['changed_state_digest']=reject(lambda:public_payload(packed(changed)),'oracle digest mismatch')
        fragments=private_fragments(data)
        for path in (*root.glob('scripts/*action33_variant_37.py'),*root.glob('reconstruction/*action33-variant-37.ts'),
                     *root.glob('reports/*action33-variant-37.md'),*root.glob('evidence/*action33-variant-37*'),
                     root/'scripts/check-research.mjs',root/'coordination/QUEUE.md'):
            raw=path.read_bytes();scan(raw,fragments)
            if path.suffix=='.bin':scan(expand(raw),fragments)
        failures['private_raw_fragment']=reject(lambda:scan(b'x'+fragments[0]+b'y',fragments),'private original fragment')
        failures['private_hex_fragment']=reject(lambda:scan(fragments[0].hex().upper().encode(),fragments),'private original fragment')
        failures['compressed_private_fragment']=reject(lambda:scan(expand(packed({'probe':fragments[-1].hex()})),fragments),'private original fragment')
        start,end=next((start,end) for start,end in task.RANGES if end-start>=33)
        off=pe_offset(data,start,end-start);late=data[off+1:off+33]
        need(late in fragments,'offset-one private window missing')
        failures['private_offset1_raw_fragment']=reject(lambda:scan(b'x'+late+b'y',fragments),'private original fragment')
        failures['private_offset1_hex_fragment']=reject(lambda:scan(late.hex().upper().encode(),fragments),'private original fragment')
        for prefix in range(3):
            encoded=base64.b64encode(b'\x01'*prefix+late+b'\x02'*4)
            failures[f'private_offset1_base64_prefix{prefix}']=reject(lambda:scan(encoded,fragments),'private original fragment')
    return {'unit':'R37-B','status':'passed','oracle_sha256':sha(retained),'specimen_sha256':task.p.EXPECTED,
      'coverage':oracle['coverage'],'normal_optimized':'byte-identical original instruction regeneration',
      'negative_checks':failures,'privacy':'bounded canonical gzip, fixed synthetic schedule and overlapping raw/hex/base64 original-code scans',
      'scope':'original-entry variant RNG and caller to pre-keeper or diagnostic; keeper machine ABI and full R30-C state join remain open'}


if __name__=='__main__':
    args=task.parser().parse_args();result=verify(args);args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(result['status'],len(result['negative_checks']))
