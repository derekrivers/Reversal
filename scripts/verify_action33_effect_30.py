#!/usr/bin/env python3
"""R30-B deterministic regeneration and explicit integrity/domain negatives."""
import gzip
import json
import math
from pathlib import Path
import shutil
import struct
import tempfile

from emulate_action33_effect_30 import generate,continue_case,LOOKUP,STOP
from extract_action33_effect_30 import parser,extract,instructions,RANGES
import emulate_action33_prefix_30 as prefix
from extract_action33_prefix_30 import compare,rows
from emulate_action33_prefix_30 import need,sha,packed,compact


def rejects(fn,text):
    try:fn()
    except (ValueError,RuntimeError) as e:
        need(text in str(e),'wrong rejection: '+str(e));return str(e)
    raise ValueError('mutation accepted: '+text)


def verify(a):
    root=Path(__file__).resolve().parents[1];sites=extract(a.binary,a.exports09,a.exports10,a.runtime)
    encoded=(json.dumps(sites,indent=2)+'\n').encode()
    need(encoded==(root/'evidence/action33-effect-30-sites.json').read_bytes(),'static regeneration changed')
    result,_=generate(a);oracle=packed(result)
    need(oracle==(root/'evidence/action33-effect-30-oracle.bin').read_bytes(),'continuation regeneration changed')
    data=a.binary.read_bytes();insns,_=instructions(data);p_ins,_=prefix.decode(data)
    mutated=bytearray(data);mutated[0x2cfe10]^=1
    failures={'changed_PE':rejects(lambda:instructions(bytes(mutated)),'specimen size/SHA-256 mismatch')}
    native=rows(a.exports10/'0062ed70.asm');native[0x62ed83]='JNZ 0x0062ed85'
    failures['independently_changed_native_operand']=rejects(lambda:compare({k:v for k,v in insns.items() if 0x62ed70<=k<STOP},native),'native operand mismatch 0062ed83')
    (root/'results').mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='action33-effect-',dir=root/'results') as tmp:
        folder=Path(tmp)
        for name in ('006cfe10.asm','006cfe10.c','00702050.asm'):shutil.copyfile(a.exports09/name,folder/name)
        path=folder/'006cfe10.asm';path.write_bytes(path.read_bytes()+b'\n')
        failures['changed_native_file']=rejects(lambda:extract(a.binary,folder,a.exports10,a.runtime),'native export digest mismatch')
    baseline=json.loads(gzip.decompress((root/'evidence/action33-prefix-30-oracle.bin').read_bytes()))['cases'][0]
    admitted=dict(insns);admitted.update({k:v for k,v in p_ins.items() if 0x90cfc0<=k<0x90d02d or 0x946a04<=k<0x946a22})
    def prepared():
        machine=prefix.Oracle(data,code_ranges=prefix.RANGES+RANGES)
        machine.uc.mem_map(prefix.MATCH,0x10000);machine.uc.mem_map(prefix.POSITIONS,0x1000)
        machine.uc.mem_write(prefix.TABLE,(root/'evidence/random-validation/random-table.bin').read_bytes())
        machine.uc.mem_write(prefix.GRID,struct.pack('<108f',*[math.hypot(x,y) for y in range(12) for x in range(9)]))
        r,_,_=prefix.run_case(machine,p_ins,prefix.make_case(0));need(compact(r)==compact(baseline),'negative prefix mismatch')
        return machine
    machine=prepared();shooter=baseline['boundary_registers']['esi']
    machine.put(shooter+0x69,0x4500000)
    failures['invented_player_pointer']=rejects(lambda:continue_case(machine,admitted,prefix.make_case(0),baseline),'unexpected supplied player/attribute pointers')
    machine=prepared();machine.put(LOOKUP,0x4500000)
    failures['invented_lookup_object']=rejects(lambda:continue_case(machine,admitted,prefix.make_case(0),baseline),'lookup global is not original zero-mapped image state')
    machine=prepared();machine.put(baseline['boundary_registers']['esp']+12,0)
    failures['normalized_fourth_dword']=rejects(lambda:continue_case(machine,admitted,prefix.make_case(0),baseline),'raw argument frame changed')
    machine=prepared();continue_case(machine,admitted,prefix.make_case(0),baseline)
    failures['crossing_diagnostic_boundary']=rejects(lambda:machine.uc.emu_start(STOP,0x3000000,count=1),'0x62ed99')
    return {'unit':'R30-B','status':'passed','specimen_sha256':sha(data),'sites_sha256':sha(encoded),
      'oracle_sha256':sha(oracle),'cases':160,'effect_returns':0,'diagnostic_stops':160,
      'integrity':'explicit exceptions; normal and -O produce identical retained bytes',
      'negative_checks':failures,
      'privacy':'only fixed synthetic input-derived scalars, addresses, call/RNG/events and full-region/trace digests are retained; private full traces stay in results/',
      'scope':'connected original execution to an unsupported diagnostic call; no effect return or TypeScript equivalence'}


if __name__=='__main__':
    a=parser().parse_args();r=verify(a);a.output.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(r['status'],r['cases'],len(r['negative_checks']))
