#!/usr/bin/env python3
"""R32-A normal/-O reproduction, fail-closed integrity and bounded privacy gates."""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zlib
import emulate_action33_opponent_32 as task
from emulate_action33_prefix_30 import need,sha,compact,packed,hx,pe_offset
from extract_action33_prefix_30 import rows,compare


class BytesFile:
    def __init__(self,data):self.data=data
    def read_bytes(self):return self.data


def rejects(work,reason):
    try:work()
    except (ValueError,RuntimeError) as error:
        need(reason in str(error),'wrong rejection: '+str(error));return reason
    raise ValueError('mutation accepted: '+reason)


def keys(value,names):need(set(value)==set(names.split()),'unexpected public fields')


def expand(blob):
    need(len(blob)<500000 and blob[:10]==bytes.fromhex('1f8b08000000000002ff'),'noncanonical gzip envelope')
    decoder=zlib.decompressobj(31);raw=decoder.decompress(blob,6000001)
    need(len(raw)<=6000000 and not decoder.unconsumed_tail,'oversized public payload')
    need(decoder.eof and not decoder.unused_data,'trailing or incomplete gzip payload')
    return raw


def public_payload(blob):
    raw=expand(blob);o=json.loads(raw);need(raw==compact(o)+b'\n' and blob==packed(o),'noncanonical public payload')
    keys(o,'unit sites cases scope coverage');need(o['unit']=='R32-A','wrong unit');need(len(o['cases'])==len(task.schedule()),'changed case count')
    constants={hx(a):struct_value for a,struct_value in ((0x96d810,'409a400000000000'),(0x968e18,'4004000000000000'))}
    for n,row in enumerate(o['cases']):
        keys(row,'id case before checkpoint after stop calls events instruction_trace memory_sha256');need(row['id']==n,'case ID changed')
        need(row['case']==task.schedule()[n],'not the fixed synthetic schedule')
        need(row['stop']==('0071614b' if row['case']['mode']=='flag-set' else '00702193'),'unexpected stop')
        keys(row['checkpoint'],'state memory_sha256 trace_length event_length')
        for digests,names in ((row['memory_sha256'],task.REGIONS),(row['checkpoint']['memory_sha256'],task.g.REGIONS)):
            need(set(digests)==set(names),'unexpected memory region')
            for value in digests.values():need(len(value)==64 and set(value)<=set('0123456789abcdef'),'unexpected memory payload')
        for pc,kind,address,size,value in row['events']:
            need(kind in ('read','write'),'unexpected memory kind')
            if size==8:need(kind=='read' and constants.get(address)==value,'unexpected qword operand')
            else:need(size in (1,2,4) and type(value)==int and 0<=value<2**(8*size),'unexpected memory operand')
            a=int(address,16);need(any(base<=a and a+size<=base+length for base,length in task.REGIONS.values()),'non-synthetic operand region')
        snapshots=[row['before'],row['checkpoint']['state'],row['after']]
        for call in row['calls']:
            keys(call,'site target before arguments after');expected=task.CALLS.get(int(call['site'],16))
            need(expected and call['target']==hx(expected[0]) and len(call['arguments'])==expected[1],'unexpected call')
            need(all(type(v)==int and 0<=v<=0xffffffff for v in call['arguments']),'unexpected call arguments')
            snapshots.append(call['before'])
            if call['after'] is not None:snapshots.append(call['after'])
            else:need(row['stop']=='0071614b' and call['site'] in ('0070210b','006d59f0'),'unexpected incomplete call')
        for snapshot in snapshots:
            keys(snapshot,'registers eflags fpcw fpsw fptag active_x87 rng rng_cells');keys(snapshot['registers'],'eax ebx ecx edx esi edi ebp esp')
            need(all(type(v)==int and 0<=v<=0xffffffff for v in snapshot['registers'].values()),'unexpected register payload')
            keys(snapshot['rng'],'cursorIndex offset crtState');keys(snapshot['rng_cells'],'00de1f60 00de1f5c 00de2798 00ad6c30')
            for value in snapshot['active_x87']:
                keys(value,'physical significand exponent');need(value['physical']==7 and len(value['significand'])==16 and set(value['significand'])<=set('0123456789abcdef'),'unexpected x87 payload')
    return o


def forbidden(data):
    fragments=[]
    for a,b in task.RANGES+((task.p.GRID,task.p.GRID+432),):
        off=pe_offset(data,a,b-a);body=data[off:off+b-a]
        for k in range(0,len(body)-31,16):
            fragment=body[k:k+32]
            if len(set(fragment))>5:fragments.append(fragment)
    need(bool(fragments),'no privacy fragments');return fragments


def private_scan(payload,fragments):
    # Both compressed bytes and bounded expanded bytes are checked by the caller.
    lower=payload.lower()
    for raw in fragments:need(raw not in payload and raw.hex().encode() not in lower,'private original fragment')


def verify(a):
    root=Path(__file__).resolve().parents[1];(root/'results').mkdir(parents=True,exist_ok=True)
    retained=(root/'evidence/action33-opponent-32-oracle.bin').read_bytes();o=public_payload(retained)
    with tempfile.TemporaryDirectory(prefix='opponent-32-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            subprocess.run([sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_opponent_32.py'),str(a.binary),
              '--fresh',str(a.fresh),'--caller',str(a.caller),'--output',str(output)],check=True,capture_output=True)
            need(output.read_bytes()==retained,'normal/-O regeneration changed')
        data,ins,_=task.extract(a.binary,a.fresh,a.caller);changed=bytearray(data);changed[pe_offset(data,0x6d59b0,1)]^=1
        failures={'changed_PE':rejects(lambda:task.extract(BytesFile(changed),a.fresh,a.caller),'specimen SHA-256/size mismatch')}
        native=rows(a.fresh/'006d59b0.asm');native[0x6d59e7]='MOV AL,byte ptr [ESI + 0x1a]'
        failures['independent_native_operand']=rejects(lambda:compare({k:v for k,v in ins.items() if 0x6d59b0<=k<0x6d5a0d},native),'native operand mismatch 006d59e7')
        fresh=folder/'native';fresh.mkdir()
        for name in ('manifest.json',*[stem+ext for stem in task.FILES for ext in ('.asm','.c')]):shutil.copyfile(a.fresh/name,fresh/name)
        path=fresh/'006d59b0.asm';path.write_bytes(path.read_bytes()+b'\n')
        failures['changed_native_file']=rejects(lambda:task.extract(a.binary,fresh,a.caller),'native file mismatch')
        path=fresh/'manifest.json';path.write_bytes(path.read_bytes()+b' ')
        failures['changed_manifest']=rejects(lambda:task.extract(a.binary,fresh,a.caller),'native manifest mismatch')
        schedule=task.schedule;task.schedule=lambda:[{'source_case':0,'mode':'all-active','flag':4}]
        try:failures['unannounced_bit04_path']=rejects(lambda:task.generate(a),'unexpected stop')
        finally:task.schedule=schedule
        seed=task.seed
        def invalid_seed(machine,c):
            result=seed(machine,c);machine.uc.mem_write(result[1]+0x102,b'\x80');return result
        task.seed=invalid_seed
        try:failures['original_out_of_grid_read']=rejects(lambda:task.generate(a),'unadmitted data access')
        finally:task.seed=seed
        changed=gzip.compress(expand(retained)+b' ',compresslevel=9,mtime=0);changed=changed[:9]+b'\xff'+changed[10:]
        failures['appended_json_whitespace']=rejects(lambda:public_payload(changed),'noncanonical public payload')
        failures['alternate_gzip_envelope']=rejects(lambda:public_payload(retained[:9]+b'\x03'+retained[10:]),'noncanonical gzip envelope')
        failures['oversized_expansion']=rejects(lambda:expand(packed('x'*6000001)),'oversized public payload')
        fragments=forbidden(data)
        for ext in ('*.py','*.ts','*.md','*.json','*.bin'):
            for path in root.rglob(ext):
                if 'action33-opponent-32' not in path.name and 'action33_opponent_32' not in path.name:continue
                if 'results' in path.parts:continue
                raw=path.read_bytes();private_scan(raw,fragments)
                if path.suffix=='.bin':private_scan(expand(raw),fragments)
        failures['private_raw_fragment']=rejects(lambda:private_scan(b'prefix'+fragments[0]+b'suffix',fragments),'private original fragment')
        failures['private_hex_fragment']=rejects(lambda:private_scan(b'prefix'+fragments[0].hex().upper().encode()+b'suffix',fragments),'private original fragment')
        compressed=packed({'probe':fragments[-1].hex()})
        failures['compressed_private_fragment']=rejects(lambda:private_scan(expand(compressed),fragments),'private original fragment')
    return {'unit':'R32-A','status':'passed','oracle_sha256':sha(retained),'specimen_sha256':task.p.EXPECTED,'coverage':o['coverage'],
      'normal_optimized':'byte-identical original instruction regeneration; all integrity gates use explicit exceptions',
      'negative_checks':failures,'privacy':'fixed synthetic schedules; bounded gzip expansion; raw/hex original code and grid fragment scans on task files and expanded oracle; original inputs absent',
      'scope':'synthetic original-entry execution to pre-00702193 or pre-0071614b; no original-game observation or connected shot outcome'}


if __name__=='__main__':
    a=task.g.parser().parse_args();result=verify(a);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(result['status'],len(result['negative_checks']))
