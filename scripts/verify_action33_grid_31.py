#!/usr/bin/env python3
"""R31-A normal/-O regeneration, admission negatives and public privacy gates."""
import copy
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import emulate_action33_grid_31 as task
from emulate_action33_prefix_30 import need,sha,compact,packed,hx
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


def public_payload(blob):
    need(len(blob)<300000 and blob[:10]==bytes.fromhex('1f8b08000000000002ff'),'noncanonical gzip envelope')
    raw=gzip.decompress(blob);need(len(raw)<4000000,'oversized public payload');o=json.loads(raw)
    need(raw==compact(o)+b'\n' and blob==packed(o),'noncanonical public payload')
    keys(o,'unit sites cases scope coverage');need(o['unit']=='R31-A','wrong unit')
    need(len(o['cases'])==750,'changed case count')
    for n,row in enumerate(o['cases']):
        keys(row,'id case before after calls events instruction_trace memory_sha256');need(row['id']==n,'case ID changed')
        need(row['case']==task.schedule()[n],'not the fixed synthetic schedule')
        keys(row['memory_sha256'],'match positions stack random_table grid')
        for value in row['memory_sha256'].values():need(len(value)==64 and set(value)<=set('0123456789abcdef'),'unexpected memory payload')
        for pc,kind,address,size,value in row['events']:
            need(kind in ('read','write') and size in (1,2,4) and type(value)==int and 0<=value<2**(8*size),'unexpected memory operand')
            a=int(address,16);need(any(base<=a and a+size<=base+length for base,length in task.REGIONS.values()),'non-synthetic operand region')
        for snapshot in (row['before'],row['after'],*[c[k] for c in row['calls'] for k in ('before','after')]):
            keys(snapshot,'registers eflags fpcw fpsw fptag active_x87 rng rng_cells')
            keys(snapshot['registers'],'eax ebx ecx edx esi edi ebp esp')
            need(all(type(v)==int and 0<=v<=0xffffffff for v in snapshot['registers'].values()),'unexpected register payload')
            keys(snapshot['rng'],'cursorIndex offset crtState');keys(snapshot['rng_cells'],'00de1f60 00de1f5c 00de2798 00ad6c30')
            for value in snapshot['active_x87']:
                keys(value,'physical significand exponent');need(value['physical']==7 and len(value['significand'])==16 and set(value['significand'])<=set('0123456789abcdef'),'unexpected x87 payload')
        for call in row['calls']:
            keys(call,'site target before arguments after');need(call['site']=='00702088' and call['target']=='006f09b0','unexpected call')
    return o


def verify(a):
    root=Path(__file__).resolve().parents[1];(root/'results').mkdir(parents=True,exist_ok=True)
    retained=(root/'evidence/action33-grid-31-oracle.bin').read_bytes();o=public_payload(retained)
    with tempfile.TemporaryDirectory(prefix='grid-31-',dir=root/'results') as folder:
        folder=Path(folder)
        for flags in ([],['-O']):
            output=folder/('optimized.bin' if flags else 'normal.bin')
            subprocess.run([sys.executable,'-B',*flags,str(root/'scripts/emulate_action33_grid_31.py'),str(a.binary),
              '--fresh',str(a.fresh),'--caller',str(a.caller),'--output',str(output)],check=True,capture_output=True)
            need(output.read_bytes()==retained,'normal/-O regeneration changed')
        data,ins,_=task.extract(a.binary,a.fresh,a.caller);changed=bytearray(data);changed[task.p.pe_offset(data,task.HELPER,1)]^=1
        failures={'changed_PE':rejects(lambda:task.extract(BytesFile(changed),a.fresh,a.caller),'specimen SHA-256/size mismatch')}
        native=rows(a.fresh/'006f09b0.asm');native[task.HELPER]='MOVSX EAX,byte ptr [ECX + 0x102]'
        failures['independent_native_operand']=rejects(lambda:compare({k:v for k,v in ins.items() if task.HELPER<=k<0x6f09ed},native),'native operand mismatch 006f09b0')
        fresh=folder/'native';fresh.mkdir()
        for name in ('manifest.json','006f09b0.asm','006f09b0.c'):shutil.copyfile(a.fresh/name,fresh/name)
        path=fresh/'006f09b0.asm';path.write_bytes(path.read_bytes()+b'\n')
        failures['changed_native_file']=rejects(lambda:task.extract(a.binary,fresh,a.caller),'native file mismatch')
        path=fresh/'manifest.json';path.write_bytes(path.read_bytes()+b' ')
        failures['changed_manifest']=rejects(lambda:task.extract(a.binary,fresh,a.caller),'native manifest mismatch')
        schedule=task.schedule;bad=copy.copy(schedule()[160]);bad['slot_x']=128
        task.schedule=lambda:[bad]
        try:failures['original_out_of_grid_read']=rejects(lambda:task.generate(a),'unadmitted data access')
        finally:task.schedule=schedule
        changed=gzip.compress(gzip.decompress(retained)+b' ',compresslevel=9,mtime=0);changed=changed[:9]+b'\xff'+changed[10:]
        failures['appended_json_whitespace']=rejects(lambda:public_payload(changed),'noncanonical public payload')
        failures['alternate_gzip_envelope']=rejects(lambda:public_payload(retained[:9]+b'\x03'+retained[10:]),'noncanonical gzip envelope')
    return {'unit':'R31-A','status':'passed','oracle_sha256':sha(retained),'specimen_sha256':task.p.EXPECTED,
      'coverage':o['coverage'],'normal_optimized':'byte-identical original instruction regeneration and explicit exception gates',
      'negative_checks':failures,'privacy':'fixed synthetic schedules/grids; all retained operands are synthetic data or code addresses; original grid/PE/native inputs retained only as hashes',
      'scope':'helper returns and resolver entry to pre-0070210b; empty x87 payloads excluded; no resolver or shot completion'}


if __name__=='__main__':
    a=task.parser().parse_args();result=verify(a);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(result['status'],len(result['negative_checks']))
