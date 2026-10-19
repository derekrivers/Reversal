#!/usr/bin/env python3
"""Regenerate R30 static/original-execution evidence and test integrity failures.

Run identically with Python normal and -O. All tests use explicit exceptions.
"""
import json
from pathlib import Path
import shutil
import tempfile

from emulate_action33_prefix_30 import (decode,need,sha,packed,generate,run_case,make_case,
 Oracle,RANGES,MATCH,POSITIONS,TABLE,GRID)
from extract_action33_prefix_30 import parser,extract,compare,rows,verify_manifest,FRESH_MANIFEST


def rejected(fn,contains):
    try:fn()
    except (ValueError,RuntimeError) as error:
        need(contains in str(error),'wrong rejection: '+str(error));return str(error)
    raise ValueError('mutation unexpectedly accepted: '+contains)


def verify(a):
    root=Path(__file__).resolve().parents[1]
    sites=extract(a.binary,a.fresh,a.r29,a.preflight,a.caller,a.runtime)
    expected_sites=(root/'evidence/action33-prefix-30-sites.json').read_bytes()
    regenerated_sites=(json.dumps(sites,indent=2)+'\n').encode()
    need(regenerated_sites==expected_sites,'static evidence regeneration changed')
    result,_=generate(a.binary,root/'evidence/random-validation/random-table.bin')
    regenerated=packed(result);expected=(root/'evidence/action33-prefix-30-oracle.bin').read_bytes()
    need(regenerated==expected,'original-execution evidence regeneration changed')
    data=a.binary.read_bytes();insns,_=decode(data)
    bad=bytearray(data);bad[0x302050]^=1
    failures={'changed_specimen':rejected(lambda:decode(bytes(bad)),'specimen size/SHA-256 mismatch')}
    native=rows(a.fresh/'005b57c0.asm');native[0x5b57c5]=native[0x5b57c5].replace('0x5b4','0x5b5')
    failures['resealed_operand']=rejected(lambda:compare({k:v for k,v in insns.items() if 0x5b57c0<=k<0x5b57cf},native),'native operand mismatch 005b57c5')
    with tempfile.TemporaryDirectory(prefix='action33-negative-',dir=root/'results') as tmp:
        temp=Path(tmp);copy=temp/'exports';shutil.copytree(a.fresh,copy)
        path=copy/'005b57c0.asm';path.write_bytes(path.read_bytes()+b'\n')
        failures['changed_native_file']=rejected(lambda:verify_manifest(copy,FRESH_MANIFEST),'native file digest mismatch')
        table=temp/'table.bin';table.write_bytes(b'wrong synthetic table')
        failures['changed_table']=rejected(lambda:generate(a.binary,table),'synthetic table SHA-256 mismatch')
    oracle=Oracle(data,code_ranges=RANGES)
    oracle.uc.mem_map(MATCH,0x10000);oracle.uc.mem_map(POSITIONS,0x1000)
    # This negative stops before any random or grid-dependent result. The first
    # grid load must still use synthetic data, including for this rejected run.
    import math,struct
    oracle.uc.mem_write(GRID,struct.pack('<108f',*[math.hypot(x,y) for y in range(12) for x in range(9)]))
    oracle.uc.mem_write(TABLE,(root/'evidence/random-validation/random-table.bin').read_bytes())
    failures['tactical_bit04_set']=rejected(lambda:run_case(oracle,insns,make_case(0),flag_violation=True),'0x716125')
    return {'unit':'R30-A','status':'passed','integrity':'explicit exception gates; identical output under normal and -O',
      'specimen_sha256':sha(data),'sites_sha256':sha(expected_sites),'oracle_sha256':sha(expected),
      'cases':result['coverage']['cases'],'original_instruction_steps':result['coverage']['instruction_steps'],
      'rejections':failures,'privacy':'regenerated retained bytes are exactly the fixed synthetic schedule; full memory/instruction traces remain private',
      'scope':'original-instruction prefix evidence; no reconstruction equivalence claim'}


if __name__=='__main__':
    a=parser().parse_args();result=verify(a)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(result['status'],result['cases'],len(result['rejections']))
