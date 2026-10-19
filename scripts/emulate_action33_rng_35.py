#!/usr/bin/env python3
"""R35-A: execute original entry through R(0) to pre-selector-call, synthetic state."""
import argparse
import gzip
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_adjustment_34 as prior
from extract_action33_prefix_30 import rows, compare, verify_manifest, RUNTIME_MANIFEST

p, g = prior.p, prior.g
START, JOIN, STOP = prior.STOP, 0x7022fd, 0x70230c
RNG = (0x90cfc0, 0x90cfcf)
NEW_RANGES = ((START, 0x70226b), (JOIN, STOP), RNG)
RANGES = (*prior.RANGES, *NEW_RANGES)
BOUNDARIES = ((STOP, STOP+5), (0x70226b, 0x702271), (0x90cfcf, 0x90cfd5),
              (prior.prior.GUARD_STOP, prior.prior.GUARD_STOP+5))
REGIONS = prior.REGIONS
CALLS = {**prior.CALLS, START: (RNG[0], 1)}
DEPENDENCIES = {
    'scripts/emulate_action33_adjustment_34.py': '58b87d972399c97c7712514f97065d96d08de7eeaae69fc1dd4aea6cafb4e88b',
    'reconstruction/action33-adjustment-34.ts': '0c7a819c24f13d2653d785517eb8e09e79ff09edea757d85bc718a772a146da5',
    'evidence/action33-adjustment-34-oracle.bin': 'b18307489d5adeaa2026ad17f214404b5ac43a400bcecfd0fab6665713511e30',
    'evidence/action33-composition-30-oracle.bin': 'e0bf9f5d089597868ae05642fc45e5628f0f268b16a210979f2d299445fb6063',
    'evidence/action33-prefix-30-oracle.bin': '08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f',
}


def schedule():
    return prior.schedule()


def validate_table(table):
    p.need(p.sha(table) == p.TABLE_HASH, 'synthetic random table mismatch')


def extract(a):
    data, ins, previous = prior.extract(a)
    manifest = verify_manifest(a.runtime, RUNTIME_MANIFEST)
    native = rows(a.caller)
    native.update(rows(a.runtime/'0090cfc0.asm'))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    ranges = []
    for start, end in NEW_RANGES + BOUNDARIES[:3]:
        off = p.pe_offset(data, start, end-start)
        raw = data[off:off+end-start]
        decoded = {i.address:i for i in md.disasm(raw, start)}
        p.need(sum(i.size for i in decoded.values()) == len(raw), 'incomplete new range')
        compare(decoded, native)
        ins.update(decoded)
        ranges.append({'start':p.hx(start),'end_exclusive':p.hx(end),'file_offset':p.hx(off),
                       'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(decoded),
                       'executed':(start,end) in NEW_RANGES})
    p.need(ins[START].op_str == '0x90cfc0' and ins[STOP].op_str == '0x6ce110', 'call boundary changed')
    p.need(ins[0x90cfce].mnemonic == 'ret' and ins[0x90cfce].op_str == '', 'zero RNG ABI changed')
    return data, ins, {'specimen_sha256':p.EXPECTED,'dependency_hashes':DEPENDENCIES,
        'runtime_manifest_sha256':RUNTIME_MANIFEST,
        'rng_native_exports':{n:manifest['files'][n] for n in ('0090cfc0.asm','0090cfc0.c')},
        'prior_ranges':previous['ranges'],'new_ranges':ranges,
        'next_call':['0070230c','006ce110'],'projection_boundary':'007022fd',
        'alternate_stops':{'nonzero_bound':'0090cfcf','contact':'0070226b','bit04':'0071614b'}}


def generate(a, mutation=None):
    root = Path(__file__).resolve().parents[1]
    for name,digest in DEPENDENCIES.items():
        p.need(p.sha((root/name).read_bytes()) == digest, 'dependency digest mismatch '+name)
    reference = json.loads(gzip.decompress((root/'evidence/action33-adjustment-34-oracle.bin').read_bytes()))
    composition = json.loads(gzip.decompress((root/'evidence/action33-composition-30-oracle.bin').read_bytes()))
    prefix = json.loads(gzip.decompress((root/'evidence/action33-prefix-30-oracle.bin').read_bytes()))
    p.need(unicorn.__version__ == '2.1.4', 'Unicorn version mismatch')
    data, ins, sites = extract(a)
    machine = p.Oracle(data, code_ranges=RANGES+BOUNDARIES)
    u = machine.uc
    u.mem_map(p.MATCH, 0x10000)
    u.mem_map(p.POSITIONS, 0x1000)
    table = (root/'evidence/random-validation/random-table.bin').read_bytes()
    validate_table(table)
    u.mem_write(p.TABLE, table)
    result = []
    for number,c in enumerate(schedule()):
        prior.prior.seed(machine, c)
        before = g.state(machine)
        trace, events, calls, pending, suffix_states = [], [], [], [], []
        checkpoint = joined = projection = None
        pc = 0
        def capture():
            return {'state':g.state(machine),'trace_length':len(trace),'event_length':len(events),
                    'call_length':len(calls),'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}}
        def code(m,address,size,unused):
            nonlocal pc, checkpoint, joined, projection
            if pending and pending[-1][0] == address:
                _, index = pending.pop()
                calls[index]['after'] = g.state(machine)
            if address == START:
                checkpoint = capture()
                if mutation == 'bound':u.mem_write(u.reg_read(x.UC_X86_REG_ESP), struct.pack('<I',1))
            if address == 0x702246 and mutation == 'rng-cell':machine.put(p.OFFSET, machine.get(p.OFFSET)^1)
            if address == 0x70225f and mutation == 'contact':
                u.mem_write(p.MATCH+0xf5aa, struct.pack('<I',u.reg_read(x.UC_X86_REG_ESI)))
            if address == JOIN:
                joined = capture()
                p.need(before['rng'] == joined['state']['rng'] and before['rng_cells'] == joined['state']['rng_cells'], 'zero-bound RNG state changed')
                if c['mode'] == 'baseline':
                    frame,shooter = u.reg_read(x.UC_X86_REG_ESP),u.reg_read(x.UC_X86_REG_ESI)
                    source = p.make_case(c['source_case'])
                    projection = {'input':{'match':p.MATCH,'shooter':shooter,
                        'action':u.mem_read(frame+0x698,1)[0],'mode':u.mem_read(frame+0x6a4,1)[0],
                        'zeroLocalByte':u.mem_read(frame+0x30,1)[0],
                        'marker260':u.mem_read(frame+0x19,1)[0],'marker375':u.mem_read(frame+0x1a,1)[0],
                        'precisionBits':source['precision_bits']},'rng':machine.state(),
                        'match_sha256':joined['memory_sha256']['match'],'positions_sha256':joined['memory_sha256']['positions']}
                    expected = composition['cases'][c['source_case']]['checkpoint']
                    p.need(all(v == expected[k] for k,v in projection.items()), 'R30-C semantic projection mismatch')
            if address == STOP:
                u.emu_stop()
                return
            if address in (0x70226b,0x90cfcf,prior.prior.GUARD_STOP):
                raise ValueError('unsupported boundary '+p.hx(address))
            pc = address
            p.need(address in ins and any(a <= address < b for a,b in RANGES), 'unadmitted instruction '+p.hx(address))
            if checkpoint is not None:suffix_states.append({'pc':p.hx(address),'state':g.state(machine)})
            trace.append(p.hx(address))
            if address in CALLS:
                target,argc = CALLS[address]
                args = list(struct.unpack('<'+'I'*argc,u.mem_read(u.reg_read(x.UC_X86_REG_ESP),argc*4))) if argc else []
                calls.append({'site':p.hx(address),'target':p.hx(target),'before':g.state(machine),'arguments':args,'after':None})
                pending.append((address+size,len(calls)-1))
        def memory(m,kind,address,size,value,unused):
            p.need(any(base <= address and address+size <= base+n for base,n in REGIONS.values()), 'unadmitted data access '+p.hx(address))
            write = kind == unicorn.UC_MEM_WRITE
            p.need(not write or not any(base <= address < base+n for base,n,_ in prior.prior.STATIC), 'immutable scalar write')
            observed = value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            events.append([p.hx(pc),'write' if write else 'read',p.hx(address),size,f'{observed:016x}' if size==8 else observed])
        hooks = [u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(g.ENTRY,0x3000000,count=4500)
        finally:
            for hook in hooks:u.hook_del(hook)
        p.need(u.reg_read(x.UC_X86_REG_EIP) == STOP and not pending, 'did not reach selector call')
        p.need(checkpoint is not None and joined is not None, 'missing original checkpoint')
        old = next(row for row in reference['cases'] if row['case'] == c)
        p.need(checkpoint['state'] == old['after'] and checkpoint['memory_sha256'] == old['memory_sha256'] and
               trace[:checkpoint['trace_length']] == old['instruction_trace'] and
               events[:checkpoint['event_length']] == old['events'] and
               calls[:checkpoint['call_length']] == old['calls'], 'R34-A original prefix mismatch')
        after = g.state(machine)
        p.need(before['rng'] == after['rng'] and before['rng_cells'] == after['rng_cells'], 'zero-bound RNG state changed')
        call = calls[-1]
        p.need(call['site'] == p.hx(START) and call['arguments'] == [0] and call['after']['registers']['eax'] == 0, 'zero-bound RNG contract mismatch')
        p.need(call['before']['registers']['esp'] == call['after']['registers']['esp'], 'RNG callee cleaned argument')
        for name in ('ebx','ecx','edx','esi','edi','ebp'):
            p.need(call['before']['registers'][name] == call['after']['registers'][name], 'RNG register ABI changed '+name)
        rng = {'site':p.hx(START),'bound':0,'value':0,'before':call['before']['rng'],'after':call['after']['rng'],
               'cells_before':call['before']['rng_cells'],'cells_after':call['after']['rng_cells']}
        selector_arg = int.from_bytes(u.mem_read(after['registers']['esp'],4),'little')
        if c['mode'] == 'baseline':
            original = next(row for row in prefix['cases'][c['source_case']]['call_trace'] if row['site'] == p.hx(STOP))
            p.need(after['registers'] == original['before'] and after['fpcw'] == original['fpcw_before'] and
                   [selector_arg] == original['args'], 'R30-A selector boundary mismatch')
        result.append({'id':number,'case':c,'before':before,'checkpoint':checkpoint,'join_checkpoint':joined,
            'projection':projection,'after':after,'stop':p.hx(STOP),'selector_argument_dword':selector_arg,
            'calls':calls,'rng':[rng],'events':events,'instruction_trace':trace,'suffix_states':suffix_states,
            'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}})
    return {'unit':'R35-A','sites':sites,'cases':result,
        'scope':'synthetic original entry through zero-bound RNG to pre-0070230c; R30-C input projection only, no full machine-state join or outcome',
        'coverage':{'cases':len(result),'instructions':sum(len(r['instruction_trace']) for r in result),
            'events':sum(len(r['events']) for r in result),'rng_calls':len(result),
            'suffix_states':sum(len(r['suffix_states']) for r in result),
            'r30c_projections':sum(r['projection'] is not None for r in result)}}


def parser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary',type=Path)
    for name in ('fresh','caller','runtime','output'):ap.add_argument('--'+name,type=Path,required=True)
    return ap


if __name__ == '__main__':
    args = parser().parse_args()
    result = generate(args)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(p.packed(result))
    print(json.dumps(result['coverage']))
