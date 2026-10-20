#!/usr/bin/env python3
"""R39-A normal/optimized regeneration, machine mutations and privacy checks."""
import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import emulate_action33_effect_39 as task
from verify_action33_keeper_38 import snapshot, expand, scan
from verify_action33_adjustment_34 import BytesFile, reject
from emulate_action33_prefix_30 import need, sha, compact, packed, pe_offset
from extract_action33_prefix_30 import rows, compare

ORACLE='fc0771a515e0e142b3b1d1d5ffd62bebf6710aa93b258e6fa66a4cab78e8958d'
VERIFIER_DEPENDENCIES={'scripts/verify_action33_keeper_38.py':'6b1102083094c0cfe4a7a9170a482a8f88f829b45e9990b5a991f65fa4eeb091'}


def public_payload(blob):
    raw=expand(blob);value=json.loads(raw)
    need(raw==compact(value)+b'\n' and blob==packed(value),'noncanonical public payload')
    need(set(value)=={'unit','sites','cases','scope','coverage'} and value['unit']=='R39-A','public shape changed')
    need(len(value['cases'])==len(task.schedule())==232,'case count changed')
    need(value['sites']['next_calls']=={'00702332':'00944cff','0062ed99':'00944cff'},'next boundaries changed')
    need(value['sites']['dependency_hashes']==task.DEPENDENCIES,'dependency hashes changed')
    for n,row in enumerate(value['cases']):
        need(set(row)=={'id','case','before','checkpoint','after','stop','boundary','selected','calls','rng','events',
          'instruction_trace','suffix_state_sha256','suffix_states','pending_calls','effect_returned','memory_sha256'},'case shape changed')
        need(row['id']==n and row['case']==task.schedule()[n] and int(row['stop'],16) in task.STOPS,'schedule or stop changed')
        for state in (row['before'],row['after'],row['checkpoint']['state']):snapshot(state)
        need(row['rng'][0]['site']=='00702241' and row['rng'][0]['arguments']==[0],'initial RNG call changed')
        need(row['effect_returned'] is False,'effect return was supplied')
        need(row['pending_calls']==[i for i,call in enumerate(row['calls']) if call['after'] is None],'pending call status changed')
        pending=[row['calls'][i] for i in row['pending_calls']]
        need([(c['site'],c['target']) for c in pending]==([('007024b4','006cfe10'),('006cfec2','0062ed70')] if row['selected'] else []),'pending effect/lookup calls changed')
        need(row['suffix_states']==len(row['instruction_trace'])-row['checkpoint']['trace_length'],'suffix count changed')
        digest=row['suffix_state_sha256'];need(len(digest)==64 and set(digest)<=set('0123456789abcdef'),'invalid state digest')
        need((row['selected']==0)==(row['stop']=='00702332'),'null branch changed')
        need(row['stop'] not in row['instruction_trace'],'boundary call executed')
        for call in row['calls']:
            need(set(call)=={'site','target','before','after','arguments'},'call shape changed');snapshot(call['before'])
            if call['after'] is not None:snapshot(call['after'])
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
    for start,end in (*task.RANGES,*task.BOUNDARIES,(task.p.GRID,task.p.GRID+432)):
        off=pe_offset(data,start,end-start);body=data[off:off+end-start];size=min(32,len(body))
        if size<12:continue
        for n in range(len(body)-size+1):result.add(body[n:n+size])
        # Padding-free base64 windows detect longer excerpts at every alignment.
        width=min(30,len(body));width-=width%3
        for n in range(len(body)-width+1):result.add(body[n:n+width])
    need(bool(result),'missing privacy samples');return sorted(result)


def verify(a):
    root=Path(__file__).resolve().parents[1];retained=(root/'evidence/action33-effect-39-oracle.bin').read_bytes()
    for name,digest in VERIFIER_DEPENDENCIES.items():need(sha((root/name).read_bytes())==digest,'verifier dependency changed '+name)
    oracle=public_payload(retained);failures={};(root/'results').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='effect-39-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            command=[sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_effect_39.py'),str(a.binary)]
            for name in ('fresh','caller','runtime','r29','exports09','exports10'):command.extend(['--'+name,str(getattr(a,name))])
            subprocess.run([*command,'--output',str(output)],check=True,capture_output=True)
            need(output.read_bytes()==retained,'normal/-O regeneration changed')
        data,ins,_=task.extract(a)
        changed=bytearray(data);changed[pe_offset(data,0x6cfeb8,1)]^=1
        mutated=argparse.Namespace(**{**vars(a),'binary':BytesFile(changed)})
        failures['changed_PE']=reject(lambda:task.extract(mutated),'specimen SHA-256/size mismatch')
        body={address:instruction for address,instruction in ins.items() if 0x6cfe10<=address<0x6cfec7}
        native=rows(a.exports09/'006cfe10.asm');native[0x6cfeb8]='MOV EAX,dword ptr [ESI + 0x68]'
        failures['native_participant_operand']=reject(lambda:compare(body,native),'native operand mismatch 006cfeb8')
        body={address:instruction for address,instruction in ins.items() if 0x62ed70<=address<0x62ed99}
        native=rows(a.exports10/'0062ed70.asm');native[0x62ed83]='JZ 0x0062edee'
        failures['native_lookup_branch']=reject(lambda:compare(body,native),'native operand mismatch 0062ed83')
        altered=folder/'native';altered.mkdir()
        for name in ('006cfe10.asm','006cfe10.c','00702050.asm'):shutil.copy2(a.exports09/name,altered/name)
        path=altered/'006cfe10.asm';path.write_bytes(path.read_bytes()+b'\n')
        changed_args=argparse.Namespace(**{**vars(a),'exports09':altered})
        failures['changed_native_effect']=reject(lambda:task.extract(changed_args),'native export digest mismatch 006cfe10.asm')
        table=bytearray((root/'evidence/random-validation/random-table.bin').read_bytes());table[0]^=1
        failures['changed_synthetic_table']=reject(lambda:task.prior.prior.prior.prior.validate_table(table),'synthetic random table mismatch')
        old_schedule=task.schedule;task.schedule=lambda:[old_schedule()[0]]
        def same_original(mutation):
            actual=task.generate(a,mutation)['cases'][0]
            need(actual==oracle['cases'][0],'original continuation mismatch')
        try:
            failures['actual_prefix_register']=reject(lambda:task.generate(a,'prefix-register'),'R38-A original prefix mismatch')
            failures['injected_participant']=reject(lambda:task.generate(a,'participant'),'instruction outside admitted RNG ranges: 0x62edee')
            failures['injected_lookup']=reject(lambda:task.generate(a,'lookup'),'null lookup ABI changed')
            failures['normalized_fourth_argument']=reject(lambda:task.generate(a,'argument-high'),'effect argument frame overwritten')
            failures['actual_rng_cell']=reject(lambda:same_original('rng-cell'),'original continuation mismatch')
            failures['actual_selector_byte']=reject(lambda:same_original('selector-byte'),'original continuation mismatch')
            failures['actual_lookup_stack']=reject(lambda:task.generate(a,'lookup-stack'),'diagnostic frame changed')
            failures['actual_terminal_flags']=reject(lambda:same_original('flags'),'original continuation mismatch')
            failures['executed_diagnostic']=reject(lambda:task.generate(a,'execute-stop'),'diagnostic stop must not execute')
        finally:task.schedule=old_schedule
        failures['alternate_gzip_envelope']=reject(lambda:public_payload(retained[:9]+b'\x03'+retained[10:]),'noncanonical gzip envelope')
        failures['oversized_expansion']=reject(lambda:expand(packed('x'*16000001)),'oversized public payload')
        changed=json.loads(expand(retained));changed['cases'][0]['suffix_state_sha256']='0'*64
        failures['changed_state_digest']=reject(lambda:public_payload(packed(changed)),'oracle digest mismatch')
        changed=json.loads(expand(retained));changed['cases'][0]['effect_returned']=True
        failures['supplied_effect_return']=reject(lambda:public_payload(packed(changed)),'effect return was supplied')
        changed=json.loads(expand(retained));changed['cases'][0]['pending_calls']=[]
        failures['removed_pending_calls']=reject(lambda:public_payload(packed(changed)),'pending call status changed')
        fragments=private_fragments(data)
        for path in (*root.glob('scripts/*action33_effect_39.py'),*root.glob('reconstruction/*action33-effect-39.ts'),
                     *root.glob('reports/*action33-effect-39.md'),*root.glob('evidence/*action33-effect-39*')):
            raw=path.read_bytes();scan(raw,fragments)
            if path.suffix=='.bin':scan(expand(raw),fragments)
        failures['private_raw_fragment']=reject(lambda:scan(b'x'+fragments[0]+b'y',fragments),'private original fragment')
        failures['private_hex_fragment']=reject(lambda:scan(fragments[0].hex().upper().encode(),fragments),'private original fragment')
        failures['private_base64_fragment']=reject(lambda:scan(base64.b64encode(fragments[-1]),fragments),'private original fragment')
        failures['compressed_private_fragment']=reject(lambda:scan(expand(packed({'probe':fragments[-1].hex()})),fragments),'private original fragment')
        for label,address in (('effect',0x6cfe50),('grid',0xa15e84)):
            for width in (33,48,64,96):
                off=pe_offset(data,address,width);fragment=data[off:off+width]
                for prefix in range(3):
                    hidden=base64.b64encode(b'\x01'*prefix+fragment).decode('ascii')
                    probe=expand(packed({'probe':hidden}))
                    failures[f'private_base64_{label}_{width}_prefix{prefix}']=reject(lambda:scan(probe,fragments),'private original fragment')
    return {'unit':'R39-A','status':'passed','oracle_sha256':sha(retained),'specimen_sha256':task.p.EXPECTED,
      'verifier_dependency_hashes':VERIFIER_DEPENDENCIES,
      'coverage':oracle['coverage'],'normal_optimized':'byte-identical original instruction regeneration',
      'negative_checks':failures,'privacy':'bounded canonical gzip; unchanged synthetic schedule; every overlapping raw/hex window up to 32 bytes and padding-free base64 window up to 30 bytes across admitted code and original grid scanned in task files and expanded oracle',
      'scope':'original-entry effect and lookup remain pending at null participant diagnostic; no effect/lookup/resolver return, outcome or live reachability; separate R30-B 160-case domain'}


if __name__=='__main__':
    args=task.parser().parse_args();result=verify(args);args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(result['status'],len(result['negative_checks']))
