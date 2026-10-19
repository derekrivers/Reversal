#!/usr/bin/env python3
"""R34-A: original-entry action 33 helper and caller to the first RNG call."""
import argparse
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x

import emulate_action33_conversion_33 as prior
from extract_action33_prefix_30 import rows, compare

p, g = prior.p, prior.g
STOP = 0x702241
HELPER = (0x713e90, 0x713ef5)
TAIL = (0x713fba, 0x713fc0)
RANGES = ((g.ENTRY, STOP), *prior.RANGES[1:], HELPER, TAIL)
REGIONS = prior.REGIONS
CALLS = {**prior.CALLS, 0x702222: (0x713e90, 7)}


def schedule():
    return [row for row in prior.schedule() if row['mode'] not in ('flag-set', 'rounding-probe')]


def extract(a):
    data, previous, sites = prior.extract(a.binary, a.fresh, a.caller)
    native = prior.native_rows(a.caller)
    for stem in prior.FILES:
        native.update(rows(a.fresh / (stem + '.asm')))
    native.update(rows(a.fresh / '00713e90.asm'))
    manifest = json.loads((a.fresh / 'manifest.json').read_bytes())
    for suffix in ('.asm', '.c'):
        name = '00713e90' + suffix
        raw = (a.fresh / name).read_bytes()
        expected = manifest['files'][name]
        p.need(len(raw) == expected['bytes'] and p.sha(raw) == expected['sha256'], 'native helper mismatch ' + name)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    ins, ranges = {}, []
    for start, end in RANGES + ((STOP, STOP + 5), (prior.GUARD_STOP, prior.GUARD_STOP + 5)):
        offset = p.pe_offset(data, start, end - start)
        raw = data[offset:offset + end - start]
        decoded = list(md.disasm(raw, start))
        p.need(sum(i.size for i in decoded) == len(raw), 'incomplete range ' + p.hx(start))
        compare({i.address: i for i in decoded}, native)
        ins.update((i.address, i) for i in decoded)
        ranges.append({'start': p.hx(start), 'end_exclusive': p.hx(end), 'file_offset': p.hx(offset),
                       'bytes': len(raw), 'sha256': p.sha(raw), 'instructions': len(decoded),
                       'executed': start not in (STOP, prior.GUARD_STOP)})
    p.need(ins[0x702222].op_str == '0x713e90' and ins[STOP].op_str == '0x90cfc0', 'call boundary changed')
    p.need(ins[0x713eef].op_str == '0x713fba' and ins[0x713fbd].op_str == '0x1c', 'action33 helper route changed')
    sites['ranges'] = ranges
    sites['next_call'] = ['00702241', '0090cfc0']
    sites['helper_route'] = ['00713eeb', '00713eef', '00713fba', '00713fbd']
    return data, ins, sites


def generate(a, corrupt_output_at_return=False):
    p.need(unicorn.__version__ == '2.1.4', 'Unicorn version mismatch')
    data, ins, sites = extract(a)
    table = (Path(__file__).resolve().parents[1] / 'evidence/random-validation/random-table.bin').read_bytes()
    p.need(p.sha(table) == p.TABLE_HASH, 'synthetic random table mismatch')
    machine = p.Oracle(data, code_ranges=RANGES + ((STOP, STOP + 5), (prior.GUARD_STOP, prior.GUARD_STOP + 5)))
    u = machine.uc
    u.mem_map(p.MATCH, 0x10000)
    u.mem_map(p.POSITIONS, 0x1000)
    u.mem_write(p.TABLE, table)
    result = []
    for number, c in enumerate(schedule()):
        prior.seed(machine, c)
        before = g.state(machine)
        trace, events, calls, pending = [], [], [], []
        pc = 0
        checkpoint = None
        def code(m, address, size, unused):
            nonlocal pc, checkpoint
            if pending and pending[-1][0] == address:
                _, index = pending.pop()
                calls[index]['after'] = g.state(machine)
            if address == 0x702227 and corrupt_output_at_return:
                # Integrity-only mutation: perturb the helper's actual output
                # after its RET and before the caller reads it.
                pointer = calls[-1]['arguments'][6]
                p.need(u.mem_read(pointer, 2) == b'\x00\x00', 'mutation precondition failed')
                u.mem_write(pointer, b'\x01\x00')
            if address in (STOP, prior.GUARD_STOP):
                p.need(address == STOP, 'unexpected bit04 path')
                u.emu_stop()
                return
            if address == 0x702222:
                checkpoint = {'state': g.state(machine), 'trace_length': len(trace),
                              'event_length': len(events), 'call_length': len(calls),
                              'memory_sha256': {key: p.sha(bytes(u.mem_read(base, n))) for key, (base, n) in REGIONS.items()}}
            pc = address
            p.need(address in ins, 'instruction outside admitted segment ' + p.hx(address))
            trace.append(p.hx(address))
            if address in CALLS:
                target, argc = CALLS[address]
                args = list(struct.unpack('<' + 'I' * argc, u.mem_read(u.reg_read(x.UC_X86_REG_ESP), 4 * argc))) if argc else []
                calls.append({'site': p.hx(address), 'target': p.hx(target), 'before': g.state(machine),
                              'arguments': args, 'after': None})
                pending.append((address + size, len(calls) - 1))
        def memory(m, kind, address, size, value, unused):
            p.need(any(base <= address and address + size <= base + n for base, n in REGIONS.values()), 'unadmitted data access ' + p.hx(address))
            write = kind == unicorn.UC_MEM_WRITE
            p.need(not write or not any(base <= address < base + n for base, n, _ in prior.STATIC), 'immutable scalar write')
            observed = value & ((1 << (size * 8)) - 1) if write else int.from_bytes(u.mem_read(address, size), 'little')
            events.append([p.hx(pc), 'write' if write else 'read', p.hx(address), size,
                           f'{observed:016x}' if size == 8 else observed])
        hooks = [u.hook_add(unicorn.UC_HOOK_CODE, code),
                 u.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, memory)]
        try:
            u.emu_start(g.ENTRY, 0x3000000, count=4000)
        finally:
            for hook in hooks: u.hook_del(hook)
        p.need(u.reg_read(x.UC_X86_REG_EIP) == STOP and not pending, 'did not reach RNG boundary')
        p.need(checkpoint is not None, 'conversion checkpoint missing')
        after = g.state(machine)
        p.need(before['rng'] == after['rng'] and before['rng_cells'] == after['rng_cells'], 'RNG advanced before call')
        p.need(calls[-1]['site'] == '00702222' and calls[-1]['target'] == '00713e90', 'helper call missing')
        p.need(calls[-1]['arguments'][0] == 0x33 and '00713eef' in trace and
               '00713f13' not in trace, 'unsupported adjustment action route')
        output_pointer = calls[-1]['arguments'][6]
        p.need(output_pointer == calls[-1]['after']['registers']['esp'] + 0x7c, 'helper output pointer ABI mismatch')
        p.need((calls[-1]['after']['registers']['eax'] & 255) == 2 and
               u.mem_read(output_pointer, 2) == b'\x00\x00' and
               u.mem_read(after['registers']['esp'], 4) == b'\x00\x00\x00\x00', 'helper contract mismatch')
        result.append({'id': number, 'case': c, 'before': before, 'checkpoint': checkpoint, 'after': after, 'stop': p.hx(STOP),
                       'calls': calls, 'events': events, 'instruction_trace': trace,
                       'memory_sha256': {key: p.sha(bytes(u.mem_read(base, n))) for key, (base, n) in REGIONS.items()}})
    return {'unit': 'R34-A', 'sites': sites, 'cases': result,
            'scope': 'synthetic original resolver entry through action33 adjustment and caller to pre-00702241 RNG; no RNG or 007022fd join',
            'coverage': {'cases': len(result), 'instructions': sum(len(r['instruction_trace']) for r in result),
                         'events': sum(len(r['events']) for r in result), 'rng_calls': 0}}


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=Path)
    ap.add_argument('--fresh', type=Path, required=True)
    ap.add_argument('--caller', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    result = generate(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(p.packed(result))
    print(json.dumps(result['coverage']))
