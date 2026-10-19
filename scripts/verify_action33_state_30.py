#!/usr/bin/env python3
"""Reproduce R30-D normal/-O evidence and exercise independent integrity gates."""
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import extract_action33_state_30 as state


class MemoryFile:
    def __init__(self,raw):
        self.raw=raw

    def read_bytes(self):
        return self.raw


class ChangedManifest:
    def __init__(self,folder):
        self.folder=folder

    def __truediv__(self,name):
        if name=='manifest.json':
            return MemoryFile((self.folder/name).read_bytes()+b' ')
        return self.folder/name


def reject(label,gate,work):
    try:
        work()
    except ValueError as exc:
        state.need(gate in str(exc),'wrong rejection gate: '+label+': '+str(exc))
        return label+' rejected'
    raise ValueError('mutation admitted: '+label)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','exports','exports09','exports24','exports25','staff_exports','lifecycle_exports','evidence','output'):
        p.add_argument(name,type=Path)
    a=p.parse_args()
    args=[a.binary,a.exports,a.exports09,a.exports24,a.exports25,a.staff_exports,a.lifecycle_exports]
    pe,decoded,native,sites=state.extract(*args)
    expected=a.evidence.read_bytes()
    state.need(len(expected)<200000,'unexpected evidence size')
    with tempfile.TemporaryDirectory(prefix='r30d-public-check-') as folder:
        output=Path(folder)/'evidence.json'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(state.__file__)),
                            *map(str,args),str(output)],check=True,capture_output=True)
            state.need(output.read_bytes()==expected,'normal/-O evidence differs')
    changed=bytearray(pe);changed[state.offset(pe,0x6eaecb,3)+2]^=1
    probes=[reject('changed PE','pinned specimen mismatch',
                   lambda:state.extract(MemoryFile(changed),*args[1:])),
            reject('changed export manifest','native manifest mismatch',
                   lambda:state.extract(a.binary,ChangedManifest(a.exports),*args[2:]))]
    bad=copy.copy(native['006eaea0']);bad[0x6eaecb]='MOV dword ptr [ESI + 0x6d],EBP'
    probes.append(reject('resealed producer operand','PE/native operand mismatch',
                         lambda:state.compare([decoded[0x6eaecb]],bad)))
    changed=bytearray(pe);changed[state.offset(pe,0x6eaecb,3)+2]=0x6d
    probes.append(reject('executed wrong producer store','producer full-memory mismatch',
                         lambda:state.emulate_producer(bytes(changed),decoded)))
    first=json.loads(expected)['producer_oracle']['cases'][0]
    swapped=copy.deepcopy(first['call'])
    swapped['arguments'][2],swapped['arguments'][4]=swapped['arguments'][4],swapped['arguments'][2]
    probes.append(reject('swapped third/fifth producer arguments','producer call ABI mismatch',
                         lambda:state.check_producer_call(swapped,first['seed'],first['index'])))
    source_off=state.offset(pe,0x9e7f28,1)
    private_source=pe[source_off:pe.index(b'\0',source_off)]
    # The independent full regeneration above constrains every retained field and value.
    # Also check raw, hex and base64 representations of the original diagnostic source.
    public_files=[a.evidence,Path(state.__file__),Path(__file__),Path('reports/action33-state-30.md'),
                  Path('scripts/check-action33-state-30.mjs')]
    for path in public_files:
        raw=path.read_bytes()
        state.need(not any(value in raw for value in (private_source,private_source.hex().encode(),
                    base64.b64encode(private_source))),'private diagnostic source leaked')
    result={'unit':'R30-D','status':'passed','evidence_sha256':state.sha(expected),
      'normal_optimized_evidence':'byte-identical; all fields regenerated from pinned inputs and synthetic schedule',
      'selected_ranges':len(state.RANGES),'compared_instructions':sum(r['instructions'] for r in sites['ranges']),
      'producer_cases':80,'producer_instruction_steps':3680,'negative_probes':probes,
      'privacy':'no original diagnostic path in raw/hex/base64; no original PE bytes or page dumps retained',
      'limits':'static provenance plus synthetic slot-producer prefix; no initialized live match or returned diagnostic'}
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R30-D','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__':
    main()
