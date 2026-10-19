#!/usr/bin/env python3
"""R34-A deterministic reproduction, bounded payload and negative integrity gates."""
import argparse
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zlib

import capstone
import emulate_action33_adjustment_34 as task
from emulate_action33_prefix_30 import need, sha, compact, packed, hx, pe_offset
from extract_action33_prefix_30 import rows, compare


class BytesFile:
    def __init__(self, data): self.data = data
    def read_bytes(self): return self.data


def reject(run, phrase):
    try: run()
    except (ValueError, RuntimeError) as error:
        need(phrase in str(error), 'wrong rejection: ' + str(error))
        return phrase
    raise ValueError('mutation accepted: ' + phrase)


def expand(blob):
    need(len(blob) < 500000 and blob[:10] == bytes.fromhex('1f8b08000000000002ff'), 'noncanonical gzip envelope')
    stream = zlib.decompressobj(31)
    raw = stream.decompress(blob, 12000001)
    need(len(raw) <= 12000000 and not stream.unconsumed_tail, 'oversized public payload')
    need(stream.eof and not stream.unused_data, 'incomplete public payload')
    return raw


def public_payload(blob, digest):
    raw = expand(blob)
    data = json.loads(raw)
    need(raw == compact(data) + b'\n' and blob == packed(data), 'noncanonical public payload')
    need(set(data) == {'unit','sites','cases','scope','coverage'} and data['unit'] == 'R34-A', 'public shape changed')
    need(len(data['cases']) == len(task.schedule()) == 232, 'case count changed')
    need(data['coverage']['rng_calls'] == 0 and data['coverage']['cases'] == 232, 'coverage changed')
    need(data['sites']['next_call'] == ['00702241','0090cfc0'], 'next boundary changed')
    for n, row in enumerate(data['cases']):
        need(set(row) == {'id','case','before','checkpoint','after','stop','calls','events','instruction_trace','memory_sha256'}, 'case shape changed')
        need(row['id'] == n and row['case'] == task.schedule()[n] and row['stop'] == '00702241', 'schedule or stop changed')
        need(row['checkpoint']['trace_length'] < len(row['instruction_trace']), 'missing helper path')
        need('00713eef' in row['instruction_trace'] and '00713f13' not in row['instruction_trace'], 'action route changed')
        need(row['calls'][-1]['arguments'][0] == 0x33 and row['calls'][-1]['target'] == '00713e90', 'helper ABI changed')
        for snapshot in (row['before'],row['checkpoint']['state'],row['after']):
            need(set(snapshot) == {'registers','eflags','fpcw','fpsw','fptag','active_x87','rng','rng_cells'}, 'snapshot shape changed')
            need(set(snapshot['registers']) == {'eax','ebx','ecx','edx','esi','edi','ebp','esp'}, 'register shape changed')
            need(all(type(v) == int and 0 <= v <= 0xffffffff for v in snapshot['registers'].values()), 'invalid register')
        for digests in (row['checkpoint']['memory_sha256'],row['memory_sha256']):
            need(set(digests) == set(task.REGIONS), 'region shape changed')
            need(all(len(v) == 64 and set(v) <= set('0123456789abcdef') for v in digests.values()), 'invalid region hash')
        for pc, operation, address, width, value in row['events']:
            need(operation in ('read','write') and width in (1,2,4,8), 'event width/kind changed')
            numeric = int(address,16)
            need(any(base <= numeric and numeric+width <= base+length for base,length in task.REGIONS.values()), 'non-synthetic operand region')
            if width == 8: need(type(value) == str and len(value) == 16, 'qword payload changed')
            else: need(type(value) == int and 0 <= value < 1 << (8*width), 'operand payload changed')
    need(sha(blob) == digest, 'oracle digest mismatch')
    return data


def private_fragments(data):
    chunks=[]
    for first,last in task.RANGES + ((0x5b58e0,0x5b590a),):
        off=pe_offset(data,first,last-first)
        body=data[off:off+last-first]
        for n in range(0,len(body)-31,16):
            sample=body[n:n+32]
            if len(set(sample))>5:chunks.append(sample)
    need(bool(chunks), 'missing privacy samples')
    return chunks


def scan(payload, fragments):
    lower=payload.lower()
    for fragment in fragments:
        need(fragment not in payload and fragment.hex().encode() not in lower, 'private original fragment')


def verify(a):
    root=Path(__file__).resolve().parents[1]
    retained=(root/'evidence/action33-adjustment-34-oracle.bin').read_bytes()
    digest=sha(retained)
    oracle=public_payload(retained,digest)
    failures={}
    (root/'results').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='adjustment-34-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            subprocess.run([sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_adjustment_34.py'),str(a.binary),
                            '--fresh',str(a.fresh),'--caller',str(a.caller),'--output',str(output)],
                           check=True,capture_output=True)
            need(output.read_bytes() == retained, 'normal/-O regeneration changed')
        data,ins,_=task.extract(a)
        changed=bytearray(data);changed[pe_offset(data,0x713eef,1)]^=1
        mutated=argparse.Namespace(**{**vars(a),'binary':BytesFile(changed)})
        failures['changed_PE']=reject(lambda:task.extract(mutated),'specimen SHA-256/size mismatch')
        helper={addr:instruction for addr,instruction in ins.items() if 0x713e90 <= addr < 0x713ef5}
        native=rows(a.fresh/'00713e90.asm');native[0x713ea4]='MOV word ptr [EBX],0x1'
        failures['native_helper_operand']=reject(lambda:compare(helper,native),'native operand mismatch 00713ea4')
        altered=folder/'native';altered.mkdir()
        for name in ('manifest.json','00713e90.asm','00713e90.c'):
            shutil.copyfile(a.fresh/name,altered/name)
        # The extraction dependency needs the remaining prefix exports too.
        for stem in task.prior.FILES:
            for ext in ('.asm','.c'):shutil.copyfile(a.fresh/(stem+ext),altered/(stem+ext))
        path=altered/'00713e90.asm';path.write_bytes(path.read_bytes()+b'\n')
        changed_args=argparse.Namespace(**{**vars(a),'fresh':altered})
        failures['changed_native_helper']=reject(lambda:task.extract(changed_args),'native helper mismatch')
        old_seed=task.prior.seed
        def other_action(machine,c):
            result=old_seed(machine,c)
            machine.uc.mem_write(task.p.SP+4,(0x34).to_bytes(4,'little'))
            return result
        task.prior.seed=other_action
        old_schedule=task.schedule
        task.schedule=lambda:[old_schedule()[0]]
        try:failures['other_action']=reject(lambda:task.generate(a),'unsupported adjustment action route')
        finally:task.prior.seed=old_seed;task.schedule=old_schedule
        task.schedule=lambda:[old_schedule()[0]]
        try:failures['corrupt_actual_output_word']=reject(lambda:task.generate(a,corrupt_output_at_return=True),'helper contract mismatch')
        finally:task.schedule=old_schedule
        wrong=gzip.compress(expand(retained)+b' ',compresslevel=9,mtime=0)
        wrong=wrong[:9]+b'\xff'+wrong[10:]
        failures['appended_json_whitespace']=reject(lambda:public_payload(wrong,digest),'noncanonical public payload')
        failures['alternate_gzip_envelope']=reject(lambda:public_payload(retained[:9]+b'\x03'+retained[10:],digest),'noncanonical gzip envelope')
        failures['oversized_expansion']=reject(lambda:expand(packed('x'*12000001)),'oversized public payload')
        changed=json.loads(expand(retained));changed['cases'][0]['after']['registers']['eax']^=1
        failures['changed_oracle_result']=reject(lambda:public_payload(packed(changed),digest),'oracle digest mismatch')
        fragments=private_fragments(data)
        for path in (*root.glob('scripts/*action33_adjustment_34.py'),*root.glob('reconstruction/*action33-adjustment-34.ts'),
                     *root.glob('reports/*action33-adjustment-34.md'),*root.glob('evidence/*action33-adjustment-34*')):
            raw=path.read_bytes();scan(raw,fragments)
            if path.suffix=='.bin':scan(expand(raw),fragments)
        failures['private_raw_fragment']=reject(lambda:scan(b'x'+fragments[0]+b'y',fragments),'private original fragment')
        failures['private_hex_fragment']=reject(lambda:scan(fragments[0].hex().upper().encode(),fragments),'private original fragment')
        failures['compressed_private_fragment']=reject(lambda:scan(expand(packed({'probe':fragments[-1].hex()})),fragments),'private original fragment')
    return {'unit':'R34-A','status':'passed','oracle_sha256':digest,'specimen_sha256':task.p.EXPECTED,
            'coverage':oracle['coverage'],'normal_optimized':'byte-identical original instruction regeneration',
            'negative_checks':failures,'privacy':'bounded gzip expansion, fixed synthetic schedule and original code fragment scans',
            'scope':'clear original-entry action33 adjustment and caller through pre-00702241 RNG; bit04, RNG body and 007022fd join remain separate'}


if __name__ == '__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary',type=Path);ap.add_argument('--fresh',type=Path,required=True)
    ap.add_argument('--caller',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    result=verify(args)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(result['status'],len(result['negative_checks']))
