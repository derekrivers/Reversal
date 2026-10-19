#!/usr/bin/env python3
"""R35-A regeneration, public payload limits and independent mutation rejections."""
import argparse
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import emulate_action33_rng_35 as task
from verify_action33_adjustment_34 import BytesFile, reject, expand, scan
from emulate_action33_prefix_30 import need, sha, compact, packed, pe_offset
from extract_action33_prefix_30 import rows, compare

ORACLE = 'edb057f22e3b5eec75ca0583a03f0b1c291e2ec96403cbf7efb61bf8d31f3a32'


def snapshot(state):
    need(set(state) == {'registers','eflags','fpcw','fpsw','fptag','active_x87','rng','rng_cells'}, 'snapshot shape changed')
    need(set(state['registers']) == {'eax','ebx','ecx','edx','esi','edi','ebp','esp'}, 'register shape changed')
    need(all(type(v) == int and 0 <= v <= 0xffffffff for v in state['registers'].values()), 'invalid register')
    need(set(state['rng']) == {'cursorIndex','offset','crtState'} and
         set(state['rng_cells']) == {task.p.hx(a) for a in task.g.CELLS}, 'RNG shape changed')


def public_payload(blob):
    raw = expand(blob)
    value = json.loads(raw)
    need(raw == compact(value)+b'\n' and blob == packed(value), 'noncanonical public payload')
    need(set(value) == {'unit','sites','cases','scope','coverage'} and value['unit'] == 'R35-A', 'public shape changed')
    need(len(value['cases']) == len(task.schedule()) == 232, 'case count changed')
    need(value['sites']['next_call'] == ['0070230c','006ce110'], 'next boundary changed')
    need(value['sites']['dependency_hashes'] == task.DEPENDENCIES, 'dependency hashes changed')
    for n,row in enumerate(value['cases']):
        need(set(row) == {'id','case','before','checkpoint','join_checkpoint','projection','after','stop',
                         'selector_argument_dword','calls','rng','events','instruction_trace','suffix_states','memory_sha256'}, 'case shape changed')
        need(row['id'] == n and row['case'] == task.schedule()[n] and row['stop'] == '0070230c', 'schedule or stop changed')
        for state in (row['before'],row['after'],row['checkpoint']['state'],row['join_checkpoint']['state']):snapshot(state)
        need(row['before']['rng'] == row['after']['rng'] and row['before']['rng_cells'] == row['after']['rng_cells'], 'RNG advanced')
        need(len(row['rng']) == 1 and row['rng'][0]['site'] == '00702241' and row['rng'][0]['bound'] == 0 and row['rng'][0]['value'] == 0, 'RNG call changed')
        need([s['pc'] for s in row['suffix_states']] == row['instruction_trace'][row['checkpoint']['trace_length']:], 'suffix sequence changed')
        for state in row['suffix_states']:snapshot(state['state'])
        for call in row['calls']:
            need(set(call) == {'site','target','before','after','arguments'}, 'call shape changed')
            snapshot(call['before']);snapshot(call['after'])
        for digest in (row['memory_sha256'],row['checkpoint']['memory_sha256'],row['join_checkpoint']['memory_sha256']):
            need(set(digest) == set(task.REGIONS), 'region shape changed')
            need(all(len(v) == 64 and set(v) <= set('0123456789abcdef') for v in digest.values()), 'invalid region hash')
        for pc,operation,address,width,operand in row['events']:
            need(operation in ('read','write') and width in (1,2,4,8), 'event width/kind changed')
            numeric = int(address,16)
            need(any(base <= numeric and numeric+width <= base+length for base,length in task.REGIONS.values()), 'non-synthetic operand region')
            if width == 8:need(type(operand) == str and len(operand) == 16 and set(operand) <= set('0123456789abcdef'), 'qword payload changed')
            else:need(type(operand) == int and 0 <= operand < 1<<(width*8), 'operand payload changed')
    need(sha(blob) == ORACLE, 'oracle digest mismatch')
    return value


def private_fragments(data):
    result=[]
    for start,end in task.RANGES:
        off=pe_offset(data,start,end-start);body=data[off:off+end-start]
        size=min(32,len(body))
        if size < 12:continue
        for n in range(0,len(body)-size+1,16):
            sample=body[n:n+size]
            if len(set(sample))>5:result.append(sample)
    need(bool(result),'missing privacy samples')
    return result


def verify(a):
    root=Path(__file__).resolve().parents[1]
    retained=(root/'evidence/action33-rng-35-oracle.bin').read_bytes()
    oracle=public_payload(retained)
    failures={}
    (root/'results').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rng-35-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            subprocess.run([sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_rng_35.py'),str(a.binary),
                '--fresh',str(a.fresh),'--caller',str(a.caller),'--runtime',str(a.runtime),'--output',str(output)],
                check=True,capture_output=True)
            need(output.read_bytes() == retained,'normal/-O regeneration changed')
        data,ins,_=task.extract(a)
        changed=bytearray(data);changed[pe_offset(data,0x90cfce,1)]^=1
        mutated=argparse.Namespace(**{**vars(a),'binary':BytesFile(changed)})
        failures['changed_PE']=reject(lambda:task.extract(mutated),'specimen SHA-256/size mismatch')
        rng={addr:instruction for addr,instruction in ins.items() if task.RNG[0] <= addr < task.RNG[1]}
        native=rows(a.runtime/'0090cfc0.asm');native[0x90cfc2]='MOV ESI,dword ptr [ESP + 0x8]'
        failures['native_rng_operand']=reject(lambda:compare(rng,native),'native operand mismatch 0090cfc2')
        altered=folder/'runtime';shutil.copytree(a.runtime,altered)
        path=altered/'0090cfc0.asm';path.write_bytes(path.read_bytes()+b'\n')
        changed_args=argparse.Namespace(**{**vars(a),'runtime':altered})
        failures['changed_native_rng']=reject(lambda:task.extract(changed_args),'native file digest mismatch 0090cfc0.asm')
        table=bytearray((root/'evidence/random-validation/random-table.bin').read_bytes());table[0]^=1
        failures['changed_synthetic_table']=reject(lambda:task.validate_table(table),'synthetic random table mismatch')
        old_schedule=task.schedule
        task.schedule=lambda:[old_schedule()[0]]
        try:
            failures['nonzero_actual_bound']=reject(lambda:task.generate(a,mutation='bound'),'unsupported boundary 0090cfcf')
            failures['contact_branch']=reject(lambda:task.generate(a,mutation='contact'),'unsupported boundary 0070226b')
            failures['mutated_rng_state']=reject(lambda:task.generate(a,mutation='rng-cell'),'zero-bound RNG state changed')
        finally:task.schedule=old_schedule
        wrong=gzip.compress(expand(retained)+b' ',compresslevel=9,mtime=0);wrong=wrong[:9]+b'\xff'+wrong[10:]
        failures['appended_json_whitespace']=reject(lambda:public_payload(wrong),'noncanonical public payload')
        failures['alternate_gzip_envelope']=reject(lambda:public_payload(retained[:9]+b'\x03'+retained[10:]),'noncanonical gzip envelope')
        failures['oversized_expansion']=reject(lambda:expand(packed('x'*12000001)),'oversized public payload')
        changed=json.loads(expand(retained));changed['cases'][0]['suffix_states'][4]['state']['registers']['ecx']^=1
        failures['changed_suffix_register']=reject(lambda:public_payload(packed(changed)),'oracle digest mismatch')
        fragments=private_fragments(data)
        for path in (*root.glob('scripts/*action33_rng_35.py'),*root.glob('reconstruction/*action33-rng-35.ts'),
                     *root.glob('reports/*action33-rng-35.md'),*root.glob('evidence/*action33-rng-35*')):
            raw=path.read_bytes();scan(raw,fragments)
            if path.suffix=='.bin':scan(expand(raw),fragments)
        failures['private_raw_fragment']=reject(lambda:scan(b'x'+fragments[0]+b'y',fragments),'private original fragment')
        failures['private_hex_fragment']=reject(lambda:scan(fragments[0].hex().upper().encode(),fragments),'private original fragment')
        failures['compressed_private_fragment']=reject(lambda:scan(expand(packed({'probe':fragments[-1].hex()})),fragments),'private original fragment')
    return {'unit':'R35-A','status':'passed','oracle_sha256':sha(retained),'specimen_sha256':task.p.EXPECTED,
        'coverage':oracle['coverage'],'normal_optimized':'byte-identical original instruction regeneration',
        'negative_checks':failures,'privacy':'bounded canonical gzip, fixed synthetic schedule and raw/hex/expanded original-code scans',
        'scope':'clear original-entry R(0) and caller through pre-0070230c; R30-C input projection only; no full machine-state join or outcome'}


if __name__ == '__main__':
    args=task.parser().parse_args()
    result=verify(args)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(result['status'],len(result['negative_checks']))
