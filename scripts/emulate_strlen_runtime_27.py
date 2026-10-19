#!/usr/bin/env python3
"""Capture bounded original-entry 009488e0 executions with exact memory reads."""
import argparse
import gzip
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn import x86_const as x
from extract_strlen_runtime_27 import extract, need, sha, ENTRY, SIZE

SRC, STACK, STOP = 0x200000, 0x10000000, 0x30000000
SP = STACK + 0x800
REGS = {name: getattr(x, 'UC_X86_REG_'+name.upper()) for name in
        ('eax', 'ecx', 'edx', 'esp', 'ebx', 'ebp', 'esi', 'edi')}
NULS = list(range(20)) + [23, 24, 25, 31, 32, 33, 47, 48, 63, 64, 65, 79, 80, 93, 94, 95]
FILLS = [1, 0x7f, 0x80, 0xff]


def samples():
    return [(alignment, nul, fill) for alignment in range(4)
            for nul in NULS for fill in FILLS]


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
    uc.mem_map(SRC, 4096)
    uc.mem_map(STACK, 4096)
    uc.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
    state = {'source': 0, 'trace': [], 'events': []}

    def on_code(machine, address, size, user):
        label = f'{address:08x}'
        need(label in starts, 'execution escaped local body')
        state['trace'].append(label)

    def on_memory(machine, access, address, size, value, user):
        need(access == unicorn.UC_MEM_READ and size in (1, 4), 'unexpected write or read width')
        if state['source'] <= address and address+size <= state['source']+104:
            region, relative = 'source', address-state['source']
        elif SP-16 <= address and address+size <= SP+20:
            region, relative = 'stack', address-SP
        else:
            raise ValueError(f'unexpected read {address:08x}+{size} in case {state.get("case")}')
        observed = int.from_bytes(machine.mem_read(address, size), 'little')
        state['events'].append(['read', region, relative, size, observed])

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_memory)
    cases, covered, edges, steps = [], set(), set(), 0
    for index, (alignment, nul, fill) in enumerate(samples()):
        state['case'] = (index, alignment, nul, fill)
        source = SRC+0xf00+alignment
        state['source'] = source
        src = bytearray(fill if fill != 1 else 1+((i*37+index*17) % 255) for i in range(104))
        src[nul] = 0
        stack = bytearray((i*19+index*11+0x3a) & 255 for i in range(36))
        stack[16:24] = struct.pack('<II', STOP, source)
        uc.mem_write(source, bytes(src))
        uc.mem_write(SP-16, bytes(stack))
        initial = {name: (0x81200000+k*0x11100000+index*13) & 0xffffffff
                   for k, name in enumerate(REGS)}
        initial['esp'] = SP
        for name, reg in REGS.items():
            uc.reg_write(reg, initial[name])
        uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
        state['trace'], state['events'] = [], []
        uc.emu_start(ENTRY, STOP, count=1000)
        trace = state['trace']
        final = {name: uc.reg_read(reg) for name, reg in REGS.items()}
        eip = uc.reg_read(x.UC_X86_REG_EIP)
        need(eip == STOP and final['eax'] == nul and final['esp'] == SP+4,
             'return length/ABI mismatch')
        need(final['ecx'] == source and all(final[k] == initial[k] for k in
             ('ebx', 'ebp', 'esi', 'edi')), 'register preservation mismatch')
        need(trace[0] == '009488e0' and trace[-1] in static['return_sites'],
             'incomplete entry-to-return trace')
        case_edges = set(zip(trace, trace[1:]))
        need(case_edges <= expected_edges, 'unexpected CFG edge')
        covered.update(trace); edges.update(case_edges); steps += len(trace)
        need(bytes(uc.mem_read(source, 104)) == src and
             bytes(uc.mem_read(SP-16, 36)) == stack, 'unlogged memory mutation')
        cases.append({'case': index, 'alignment': alignment, 'nul': nul, 'fill': fill,
                      'source': list(src), 'stack_before': list(stack),
                      'initial': initial, 'final': final, 'eip': eip,
                      'events': state['events'], 'steps': len(trace), 'return_site': trace[-1]})
    need(covered == starts, 'instruction coverage missing: '+str(sorted(starts-covered)))
    need(edges == expected_edges, 'CFG edge coverage missing: '+str(sorted(expected_edges-edges)))
    result = {k: static[k] for k in ('unit', 'entry_va', 'specimen_sha256',
              'checkpoint_archive_sha256', 'export_manifest_sha256',
              'annotation_preflight_sha256', 'body_sha256')}
    result.update({'schema_version': 1, 'engine': 'Unicorn 2.1.4 x86 32-bit',
                   'mode': 'unpatched original entry-to-return; no callees',
                   'cases_count': len(cases), 'executed_instruction_steps': steps,
                   'covered_instruction_starts': sorted(covered),
                   'covered_cfg_edges': sorted(edges), 'cases': cases,
                   'eflags_compared': False,
                   'limits': ['synthetic stable mapped 104-byte strings and 36-byte stack',
                              'NUL positions 0..19 and selected 23..95; all alignments',
                              'no fault, race, caller formatting or locale validation']})
    need(not output.exists(), 'output must be new')
    output.write_bytes(gzip.compress((json.dumps(result, separators=(',', ':'))+'\n').encode(), mtime=0))
    print(json.dumps({'cases': len(cases), 'steps': steps, 'instruction_starts': len(covered),
                      'cfg_edges': len(edges), 'oracle_sha256': sha(output.read_bytes())}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=Path)
    p.add_argument('--exports', type=Path, required=True)
    p.add_argument('--preflight', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('evidence/strlen-runtime-27-oracle.json.gz'))
    a = p.parse_args()
    generate(a.binary, a.exports, a.preflight, a.output)
