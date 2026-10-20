#!/usr/bin/env python3
"""R38-A normal/optimized reproduction, payload/privacy limits and mutations."""
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

import emulate_action33_keeper_38 as task
from verify_action33_adjustment_34 import BytesFile, reject
from verify_action33_rng_35 import snapshot as prior_snapshot
from emulate_action33_prefix_30 import need, sha, compact, packed, pe_offset
from extract_action33_prefix_30 import rows, compare

ORACLE='d5e9ed42bae44b49a0c21dc21b6e7e045f7eb724b2b2a3f9770eddecf703a53d'


def snapshot(state):
    prior_snapshot(state)
    for name in ('eflags','fpcw','fpsw','fptag'):
        need(type(state[name])==int and 0<=state[name]<(1<<(32 if name=='eflags' else 16)),'invalid machine scalar')
    active=state['active_x87'];need(type(active)==list and len(active)<=8,'invalid x87 stack')
    need([v['physical'] for v in active]==sorted(set(v['physical'] for v in active)),'duplicate/unordered x87 slot')
    for slot in active:
        need(set(slot)=={'physical','significand','exponent'} and type(slot['physical'])==int and 0<=slot['physical']<8,'invalid x87 slot')
        need(type(slot['exponent'])==int and 0<=slot['exponent']<=65535 and len(slot['significand'])==16 and set(slot['significand'])<=set('0123456789abcdef'),'invalid x87 payload')
    need(set(v['physical'] for v in active)=={n for n in range(8) if (state['fptag']>>(2*n))&3!=3},'x87 tag/payload mismatch')
    need(all(type(v)==int and 0<=v<=0xffffffff for v in state['rng_cells'].values()),'invalid RNG cell')


def expand(blob):
    need(len(blob)<2000000 and blob[:10]==bytes.fromhex('1f8b08000000000002ff'),'noncanonical gzip envelope')
    stream=zlib.decompressobj(31);raw=stream.decompress(blob,16000001)
    need(len(raw)<=16000000 and not stream.unconsumed_tail,'oversized public payload')
    need(stream.eof and not stream.unused_data,'incomplete public payload')
    return raw


def public_payload(blob):
    raw=expand(blob);value=json.loads(raw)
    need(raw==compact(value)+b'\n' and blob==packed(value),'noncanonical public payload')
    need(set(value)=={'unit','sites','cases','scope','coverage'} and value['unit']=='R38-A','public shape changed')
    need(len(value['cases'])==len(task.schedule())==232,'case count changed')
    need(value['sites']['next_calls']=={'00702332':'00944cff','007024b4':'006cfe10'},'next boundaries changed')
    need(value['sites']['dependency_hashes']==task.DEPENDENCIES,'dependency hashes changed')
    for n,row in enumerate(value['cases']):
        need(set(row)=={'id','case','before','checkpoint','after','stop','boundary','selected','calls','rng','events',
          'instruction_trace','suffix_state_sha256','suffix_states','r30c_projection','memory_sha256'},'case shape changed')
        need(row['id']==n and row['case']==task.schedule()[n] and int(row['stop'],16) in task.STOPS,'schedule or stop changed')
        for state in (row['before'],row['after'],row['checkpoint']['state']):snapshot(state)
        need(row['rng'][0]['site']=='00702241' and row['rng'][0]['arguments']==[0],'initial RNG call changed')
        need(len(row['rng'])>=(2 if row['selected'] else 1),'RNG call count changed')
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
    for start,end in (*task.RANGES,(task.p.GRID,task.p.GRID+432)):
        off=pe_offset(data,start,end-start);body=data[off:off+end-start];size=min(32,len(body))
        if size<12:continue
        for n in range(len(body)-size+1):result.add(body[n:n+size])
        # A 32-byte base64 sample ends with '=' and cannot match inside a
        # longer encoding. Overlapping 30-byte windows have no padding and
        # include every alignment of an excerpt within a larger encoded value.
        width=min(30,len(body));width-=width%3
        for n in range(len(body)-width+1):result.add(body[n:n+width])
    need(bool(result),'missing privacy samples');return sorted(result)


def scan(payload,fragments):
    lower=payload.lower()
    for fragment in fragments:
        need(fragment not in payload and fragment.hex().encode() not in lower and base64.b64encode(fragment) not in payload,'private original fragment')


def verify(a):
    root=Path(__file__).resolve().parents[1];retained=(root/'evidence/action33-keeper-38-oracle.bin').read_bytes()
    oracle=public_payload(retained);failures={};(root/'results').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='keeper-38-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            subprocess.run([sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_keeper_38.py'),str(a.binary),
              '--fresh',str(a.fresh),'--caller',str(a.caller),'--runtime',str(a.runtime),'--r29',str(a.r29),'--output',str(output)],check=True,capture_output=True)
            need(output.read_bytes()==retained,'normal/-O regeneration changed')
        data,ins,_=task.extract(a)
        changed=bytearray(data);changed[pe_offset(data,0x6ce2f8,1)]^=1
        mutated=argparse.Namespace(**{**vars(a),'binary':BytesFile(changed)})
        failures['changed_PE']=reject(lambda:task.extract(mutated),'specimen SHA-256/size mismatch')
        body={address:instruction for address,instruction in ins.items() if 0x700420<=address<0x7004f1}
        native=rows(a.fresh/'00700420.asm');native[0x700429]='MOV EBP,dword ptr [ESP + 0x20]'
        failures['native_keeper_operand']=reject(lambda:compare(body,native),'native operand mismatch 00700429')
        altered=folder/'native';shutil.copytree(a.fresh,altered)
        path=altered/'00700420.asm';path.write_bytes(path.read_bytes()+b'\n')
        changed_args=argparse.Namespace(**{**vars(a),'fresh':altered})
        failures['changed_native_keeper']=reject(lambda:task.extract(changed_args),'native file digest mismatch 00700420.asm')
        table=bytearray((root/'evidence/random-validation/random-table.bin').read_bytes());table[0]^=1
        failures['changed_synthetic_table']=reject(lambda:task.prior.prior.prior.validate_table(table),'synthetic random table mismatch')
        old_schedule=task.schedule;task.schedule=lambda:[old_schedule()[0]]
        def same_original(mutation):
            actual=task.generate(a,mutation)['cases'][0]
            need(actual==oracle['cases'][0],'original continuation mismatch')
        try:
            failures['actual_preserved_register']=reject(lambda:task.generate(a,'return-esi'),'keeper preserved register changed esi')
            failures['actual_return_cleanup']=reject(lambda:task.generate(a,'return-esp'),'keeper RET 24 ABI mismatch')
            failures['actual_return_high_word']=reject(lambda:same_original('return-value'),'original continuation mismatch')
            failures['actual_return_x87']=reject(lambda:same_original('return-x87'),'original continuation mismatch')
            failures['actual_rng_cell']=reject(lambda:task.generate(a,'rng-cell'),'R30-C semantic projection mismatch')
            failures['actual_output_pointer']=reject(lambda:same_original('output-pointer'),'original continuation mismatch')
            failures['actual_caller_marker']=reject(lambda:task.generate(a,'caller-marker'),'R30-C semantic projection mismatch')
            failures['unsupported_action']=reject(lambda:task.generate(a,'action'),'instruction outside admitted RNG ranges: 0x7004f1')
        finally:task.schedule=old_schedule
        wrong=gzip.compress(expand(retained)+b' ',compresslevel=9,mtime=0);wrong=wrong[:9]+b'\xff'+wrong[10:]
        failures['appended_json_whitespace']=reject(lambda:public_payload(wrong),'noncanonical public payload')
        failures['alternate_gzip_envelope']=reject(lambda:public_payload(retained[:9]+b'\x03'+retained[10:]),'noncanonical gzip envelope')
        failures['oversized_expansion']=reject(lambda:expand(packed('x'*16000001)),'oversized public payload')
        changed=json.loads(expand(retained));changed['cases'][0]['suffix_state_sha256']='0'*64
        failures['changed_state_digest']=reject(lambda:public_payload(packed(changed)),'oracle digest mismatch')
        fragments=private_fragments(data)
        for path in (*root.glob('scripts/*action33_keeper_38.py'),*root.glob('reconstruction/*action33-keeper-38.ts'),
                     *root.glob('reports/*action33-keeper-38.md'),*root.glob('evidence/*action33-keeper-38*')):
            raw=path.read_bytes();scan(raw,fragments)
            if path.suffix=='.bin':scan(expand(raw),fragments)
        failures['private_raw_fragment']=reject(lambda:scan(b'x'+fragments[0]+b'y',fragments),'private original fragment')
        failures['private_hex_fragment']=reject(lambda:scan(fragments[0].hex().upper().encode(),fragments),'private original fragment')
        failures['private_base64_fragment']=reject(lambda:scan(base64.b64encode(fragments[-1]),fragments),'private original fragment')
        failures['compressed_private_fragment']=reject(lambda:scan(expand(packed({'probe':fragments[-1].hex()})),fragments),'private original fragment')
        for label,address in (('keeper',0x700a4f),('grid',0xa15e84)):
            for width in (33,48,64,96):
                off=pe_offset(data,address,width);fragment=data[off:off+width]
                for prefix in range(3):
                    # Prefixes 0/1/2 exercise every base64 group alignment.
                    hidden=base64.b64encode(b'\x01'*prefix+fragment).decode('ascii')
                    probe=expand(packed({'probe':hidden}))
                    failures[f'private_base64_{label}_{width}_prefix{prefix}']=reject(lambda:scan(probe,fragments),'private original fragment')
    return {'unit':'R38-A','status':'passed','oracle_sha256':sha(retained),'specimen_sha256':task.p.EXPECTED,
      'coverage':oracle['coverage'],'normal_optimized':'byte-identical original instruction regeneration',
      'negative_checks':failures,'privacy':'bounded canonical gzip, fixed synthetic schedule; overlapping raw/hex windows up to 32 bytes and padding-free base64 windows up to 30 bytes across admitted code and original grid scanned in public files and expanded oracle',
      'scope':'original-entry keeper return and caller to pre-effect or diagnostic; no full R30-C machine-state join, resolver return, outcome or live reachability'}


if __name__=='__main__':
    args=task.parser().parse_args();result=verify(args);args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(result['status'],len(result['negative_checks']))
