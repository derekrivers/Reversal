#!/usr/bin/env python3
"""Capture original-entry 009466d0 executions; no callee hooks or code patches."""
import argparse
import gzip
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_EXEC, UC_PROT_READ
from unicorn import x86_const as x
from extract_strncpy_runtime_26 import extract, need, sha, ENTRY, SIZE

SRC, DST, STACK, STOP = 0x200000, 0x210000, 0x10000000, 0x30000000
SP = STACK+0x800
REGS = {name: getattr(x, 'UC_X86_REG_'+name.upper()) for name in
        ('eax', 'ecx', 'edx', 'esp', 'ebx', 'ebp', 'esi', 'edi')}
COUNTS = list(range(18))+[31, 32, 33, 63, 64, 65]
NULS = [-1, 0, 1, 2, 3, 4, 7, 15, 16, 17, 31, 32, 63, 64, 65]


def samples():
    # Every source and destination alignment; NULs before/at/after count and
    # each lane of a loaded word. Special no-NUL fills exercise detector carries.
    return [(sa, da, count, nul, fill) for sa in range(4) for da in range(4)
            for count in COUNTS for nul, fill in
            [(n, -1) for n in NULS]+[(-1, 0x80), (-1, 0xff), (-1, 1)]]


def generate(binary, exports, preflight, output):
    need(unicorn.__version__ == '2.1.4', 'requires Unicorn 2.1.4')
    static = extract(binary, exports, preflight)
    raw = binary.read_bytes()
    off = int(static['file_offset'], 16)
    body = raw[off:off+SIZE]
    need(sha(body) == static['body_sha256'], 'PE body changed')
    starts = set(static['instruction_starts'])
    expected_edges = {tuple(e) for e in static['cfg_edges']}
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(ENTRY & ~4095, 4096)
    uc.mem_write(ENTRY, body)
    uc.mem_protect(ENTRY & ~4095, 4096, UC_PROT_READ | UC_PROT_EXEC)
    for page in (SRC, DST, STACK):
        uc.mem_map(page, 4096)
    uc.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
    state = {'source': 0, 'dest': 0, 'trace': [], 'events': []}

    def on_code(machine, address, size, user):
        address = f'{address:08x}'
        need(address in starts, 'execution escaped complete local body')
        state['trace'].append(address)

    def memory_region(address, size):
        for region, base, length in [('source', state['source'], 96),
                                     ('dest', state['dest'], 96), ('stack', SP-16, 36)]:
            if base <= address and address+size <= base+length:
                return region, address-(SP if region == 'stack' else base)
        raise ValueError(f'unexpected memory operand {address:08x}+{size}')

    def on_memory(machine, access, address, size, value, user):
        region, relative = memory_region(address, size)
        mode = 'read' if access == unicorn.UC_MEM_READ else 'write'
        need(size in (1, 4) and not (mode == 'write' and region == 'source') and
             not (mode == 'read' and region == 'dest'), 'unexpected memory mode/width')
        if mode == 'read':
            value = int.from_bytes(machine.mem_read(address, size), 'little')
        state['events'].append([mode, region, relative, size, value & ((1 << (8*size))-1)])

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_memory)
    cases, covered, edges, steps = [], set(), set(), 0
    for index, (sa, da, count, nul, fill) in enumerate(samples()):
        source, dest = SRC+0xf00+sa, DST+0xf00+da
        state['source'], state['dest'] = source, dest
        src = bytearray(fill if fill != -1 else 1+((i*37+index*17) % 255) for i in range(96))
        if nul >= 0:
            src[nul] = 0
        before = bytes((i*23+index*7+0xa5) & 255 for i in range(96))
        stack = bytearray((i*19+index*11+0x3a) & 255 for i in range(36))
        stack[16:32] = struct.pack('<IIII', STOP, dest, source, count)
        uc.mem_write(source, bytes(src))
        uc.mem_write(dest, before)
        uc.mem_write(SP-16, bytes(stack))
        initial = {name: (0x81200000+k*0x11100000+index*13) & 0xffffffff
                   for k, name in enumerate(REGS)}
        initial['esp'] = SP
        for name, reg in REGS.items():
            uc.reg_write(reg, initial[name])
        uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
        state['trace'], state['events'] = [], []
        uc.emu_start(ENTRY, STOP, count=5000)
        trace = state['trace']
        final = {name: uc.reg_read(reg) for name, reg in REGS.items()}
        eip = uc.reg_read(x.UC_X86_REG_EIP)
        need(eip == STOP and final['eax'] == dest and final['esp'] == SP+4,
             'return ABI mismatch')
        need(all(final[k] == initial[k] for k in ('ebx', 'ebp', 'esi', 'edi')),
             'callee-saved register changed')
        need(trace[0] == '009466d0' and trace[-1] in static['return_sites'],
             'incomplete entry-to-return trace')
        case_edges = set(zip(trace, trace[1:]))
        need(case_edges <= expected_edges, 'execution crossed unexpected CFG edge')
        covered.update(trace)
        edges.update(case_edges)
        steps += len(trace)
        after, stack_after = bytes(uc.mem_read(dest, 96)), bytes(uc.mem_read(SP-16, 36))
        need(bytes(uc.mem_read(source, 96)) == src, 'source changed')
        replay = {'dest': bytearray(before), 'stack': bytearray(stack)}
        for mode, region, relative, size, value in state['events']:
            if mode == 'write':
                offset = relative+(16 if region == 'stack' else 0)
                replay[region][offset:offset+size] = value.to_bytes(size, 'little')
        need(bytes(replay['dest']) == after and bytes(replay['stack']) == stack_after,
             'unlogged memory mutation')
        # Independent ordinary output check supplements, but does not replace,
        # the original instruction oracle or the operand-sized event comparison.
        logical = bytes(src[:count])
        if b'\0' in logical:
            z = logical.index(0)
            logical = logical[:z]+bytes(count-z)
        need(after == logical+before[count:], 'logical copy/pad output differs')
        cases.append({'case': index, 'source_alignment': sa, 'dest_alignment': da,
                      'count': count, 'nul': nul, 'fill': fill,
                      'source': list(src), 'dest_before': list(before), 'dest_after': list(after),
                      'stack_before': list(stack), 'stack_after': list(stack_after),
                      'initial': initial, 'final': final, 'eip': eip,
                      'events': state['events'], 'steps': len(trace), 'return_site': trace[-1]})
    need(covered == starts, 'instruction coverage missing: '+str(sorted(starts-covered)))
    need(edges == expected_edges, 'CFG edge coverage missing: '+str(sorted(expected_edges-edges)))
    result = {k: static[k] for k in ('unit', 'entry_va', 'specimen_sha256', 'checkpoint_archive_sha256',
              'export_manifest_sha256', 'annotation_preflight_sha256', 'body_sha256')}
    result.update({'schema_version': 1, 'engine': 'Unicorn 2.1.4, x86 32-bit',
                   'mode': 'unpatched original entry-to-return; no intercepted callees',
                   'cases_count': len(cases), 'executed_instruction_steps': steps,
                   'covered_instruction_starts': sorted(covered), 'covered_cfg_edges': sorted(edges),
                   'cases': cases, 'eflags_compared': False,
                   'limits': ['synthetic disjoint stable buffers, valid mapped stack and pointers',
                              'counts in 0..17,31,32,33,63,64,65; all sixteen alignments',
                              'no aliasing, invalid-pointer/fault, locale or caller validation']})
    need(not output.exists(), 'output must be new')
    output.write_bytes(gzip.compress((json.dumps(result, separators=(',', ':'))+'\n').encode(), mtime=0))
    print(json.dumps({'cases': len(cases), 'steps': steps, 'instruction_starts': len(covered),
                      'cfg_edges': len(edges), 'oracle_sha256': sha(output.read_bytes())}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=Path)
    p.add_argument('--exports', type=Path, required=True)
    p.add_argument('--preflight', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('evidence/strncpy-runtime-26-oracle.json.gz'))
    a = p.parse_args()
    generate(a.binary, a.exports, a.preflight, a.output)
