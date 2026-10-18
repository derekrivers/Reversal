#!/usr/bin/env python3
"""Run R26-C original entry-to-return code and switch data on synthetic records."""
import argparse
import gzip
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn import x86_const as x

from extract_league_comparator_26 import extract, need, sha, ENTRY, SIZE, TABLE

LEFT, RIGHT, SHARED, GLOBAL, STACK, STOP = 0x200000, 0x210000, 0x220000, 0xb679fc, 0x10000000, 0x30000000
SP = STACK+0x800
REGS = {name: getattr(x, 'UC_X86_REG_'+name.upper()) for name in
        ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esi', 'edi', 'esp']}
FIELDS = [0x19, 0x15, 0x17, 0x31, 0x12]


def samples():
    rows = []

    def add(label, left=None, right=None, rules=None, keys=None, alias=False):
        rows.append({'label': label, 'left_fields': left or [0]*5, 'right_fields': right or [0]*5,
                     'rules': rules or [0]*4, 'keys': keys or [1, 2], 'alias': alias})

    for keys in [[0, 0], [0, 2], [1, 0], [1, 2]]:
        add('key-guard', keys=keys)
    add('transitivity-A-B', [1, 0, 0, 0, 0], keys=[1, 0])
    add('transitivity-B-C', right=[2, 0, 0, 0, 0], keys=[0, 2])
    add('transitivity-A-C', [1, 0, 0, 0, 0], [2, 0, 0, 0, 0], keys=[1, 2])
    values = [-32768, -1, 0, 1, 32767]
    for a in values:
        for b in values:
            add('primary-boundary', [a, 0, 0, 0, 0], [b, 0, 0, 0, 0], [1, 2, 3, 5])
    for rule in range(256):
        add('all-rule-bytes', [0, -10, 2, -20, -3], [0, 10, -2, 20, 3], [rule, 0, 0, 0])
    for rule in [1, 2, 3, 5]:
        domain = [-128, -1, 0, 1, 127] if rule == 3 else values
        for position in range(4):
            for a in domain:
                for b in domain:
                    left, right = [0]*5, [0]*5
                    field = {1: 1, 2: 1, 3: 4, 5: 3}[rule]
                    left[field], right[field] = a, b
                    if rule == 1:
                        left[2], right[2] = b, a
                    add('rule-boundary-at-position', left, right, [4]*position+[rule]+[0]*(3-position))
    # Four meaningful priorities, duplicate rules, stop-at-zero, unknown skips and same-row alias.
    for rules in [[1, 2, 3, 5], [5, 3, 2, 1], [4]*4, [255, 128, 6, 4],
                  [0, 1, 2, 5], [4, 0, 1, 2], [2, 2, 2, 2], [1]*4]:
        add('equal-fields', rules=rules)
        add('stable-same-row-alias', [1, -32768, 32767, -4, -128], rules=rules, alias=True)
    # Differing later keys with every earlier meaningful rule tied.
    for rules in [[1, 2, 3, 5], [5, 3, 2, 1]]:
        for position in range(4):
            left, right = [0]*5, [0]*5
            rule = rules[position]
            if rule == 1:
                right[2] = 1
            elif rule == 2:
                right[1] = right[2] = 1
            else:
                right[{3: 4, 5: 3}[rule]] = 1
            add('meaningful-priority', left, right, rules)
    # Deterministic synthetic combinations, with primary equality to reach rules.
    seed = 0x261968
    for n in range(128):
        def draw():
            nonlocal seed
            seed = (seed*1664525+1013904223) & 0xffffffff
            return seed
        left = [0]+[(draw() >> 8) % 65536-32768 for _ in range(3)]+[(draw() >> 16) % 256-128]
        right = [0]+[(draw() >> 8) % 65536-32768 for _ in range(3)]+[(draw() >> 16) % 256-128]
        add('synthetic-combinations', left, right, [(draw() >> 16) % 8 for _ in range(4)])
    return rows


def generate(binary, exports, preflight, output):
    need(unicorn.__version__ == '2.1.4', 'requires Unicorn 2.1.4')
    static = extract(binary, exports, preflight)
    raw = binary.read_bytes()
    off, table_off = int(static['file_offset'], 16), int(static['switch_table']['file_offset'], 16)
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(ENTRY & ~4095, 4096)
    uc.mem_write(ENTRY, raw[off:off+SIZE])
    uc.mem_write(TABLE, raw[table_off:table_off+20])
    uc.mem_protect(ENTRY & ~4095, 4096, UC_PROT_READ | UC_PROT_EXEC)
    for a in [LEFT, RIGHT, SHARED, GLOBAL & ~4095]:
        uc.mem_map(a, 4096, UC_PROT_READ)
    uc.mem_map(STACK, 4096)
    uc.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
    starts = {int(a, 16) for a in static['instruction_starts']}
    logs = {'trace': [], 'events': []}

    def code(machine, address, size, user):
        need(address in starts, 'execution escaped complete local body')
        logs['trace'].append(f'{address:08x}')

    def read(machine, access, address, size, value, user):
        need(any(a <= address and address+size <= a+4096 for a in
                 [LEFT, RIGHT, SHARED, GLOBAL & ~4095, STACK]) or TABLE <= address and address+size <= TABLE+20,
             'read escaped admitted synthetic memory')
        logs['events'].append(['r', address, size, int.from_bytes(machine.mem_read(address, size), 'little')])

    def write(machine, access, address, size, value, user):
        need(SP-16 <= address and address+size <= SP, 'write escaped four stack save slots')
        logs['events'].append(['w', address, size, value & ((1 << (8*size))-1)])

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_READ, read)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    cases, covered, edges, steps = [], set(), set(), 0
    for n, row in enumerate(samples()):
        lp, rp, shared = LEFT+0x100+n % 4, RIGHT+0x100+(n//4) % 4, SHARED+n % 4
        records = []
        for j in range(2):
            data = bytearray((i*17+n*3+j*11) & 255 for i in range(59))
            struct.pack_into('<I', data, 0, row['keys'][j])
            for field, value in zip(FIELDS, row['left_fields' if j == 0 else 'right_fields']):
                struct.pack_into('<b' if field == 0x12 else '<h', data, field, value)
            records.append(bytes(data))
        uc.mem_write(lp, records[0])
        uc.mem_write(rp, records[1])
        if row['alias']:
            rp = lp
            records[1] = records[0]
        uc.mem_write(shared+0xc5, bytes(row['rules']))
        uc.mem_write(GLOBAL, struct.pack('<I', shared))
        initial = {name: ((0xa1200000+k*0x01110000+n*257) & 0xffffffff)
                   for k, name in enumerate(REGS)}
        initial['esp'] = SP
        stack = bytes((i*13+n*7) & 255 for i in range(28))
        uc.mem_write(SP-16, stack)
        uc.mem_write(SP, struct.pack('<III', STOP, lp, rp))
        before = bytes(uc.mem_read(SP-16, 28))
        for name, register in REGS.items():
            uc.reg_write(register, initial[name])
        uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
        for log in logs.values():
            log.clear()
        uc.emu_start(ENTRY, STOP, count=250)
        final = {name: uc.reg_read(register) for name, register in REGS.items()}
        need(uc.reg_read(x.UC_X86_REG_EIP) == STOP and final['esp'] == SP+4, 'return ABI mismatch')
        need(all(initial[k] == final[k] for k in ['ebx', 'ebp', 'esi', 'edi']), 'callee-saved register changed')
        need(logs['trace'][0] == '006834f0' and logs['trace'][-1] in static['returns'], 'incomplete entry-to-return trace')
        after = bytes(uc.mem_read(SP-16, 28))
        replay = bytearray(before)
        for kind, address, size, value in logs['events']:
            if kind == 'w':
                replay[address-(SP-16):address-(SP-16)+size] = value.to_bytes(size, 'little')
        need(bytes(replay) == after, 'unlogged stack mutation')
        trace = logs['trace']
        edges.update(zip(trace, trace[1:]))
        covered.update(trace)
        steps += len(trace)
        cases.append({'case': n, **row, 'left_address': lp, 'right_address': rp, 'shared_address': shared,
                      'left_record': list(records[0]), 'right_record': list(records[1]),
                      'initial': initial, 'final': final, 'stack_before': list(before), 'stack_after': list(after),
                      'events': list(logs['events']), 'trace': list(trace)})
    need(covered == set(static['instruction_starts']), 'missing reachable instruction coverage')
    for a, targets in static['branches'].items():
        need(all((a, target) in edges for target in targets), 'missing taken CFG edge at '+a)
    result = {'schema_version': 1, 'unit': 'R26-C', 'origin': 'synthetic stable records, shared rules and stack',
              'entry_va': f'{ENTRY:08x}', 'specimen_sha256': static['specimen_sha256'],
              'checkpoint_archive_sha256': static['checkpoint_archive_sha256'],
              'export_manifest_sha256': static['export_manifest_sha256'],
              'annotation_preflight_sha256': static['annotation_preflight_sha256'],
              'body_sha256': static['body_sha256'], 'switch_table_sha256': static['switch_table']['sha256'],
              'cases_count': len(cases), 'executed_instruction_steps': steps,
              'covered_instruction_starts': sorted(covered), 'covered_edges': [list(p) for p in sorted(edges)],
              'all_branch_and_switch_edges_executed': True, 'cases': cases,
              'limits': ['valid mapped stable records and shared pointer; stack disjoint from inputs',
                         'no concurrent mutation, invalid pointer or caller sorting execution',
                         'EFLAGS not compared; caller-saved integer registers and all data/stack events compared']}
    need(not output.exists(), 'output must be a new file')
    payload = (json.dumps(result, separators=(',', ':'))+'\n').encode('utf-8')
    output.write_bytes(gzip.compress(payload, compresslevel=9, mtime=0))
    print(json.dumps({'cases': len(cases), 'steps': steps, 'instructions': len(covered),
                      'gzip_oracle_sha256': sha(output.read_bytes()), 'json_sha256': sha(payload)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=Path)
    p.add_argument('--exports', type=Path, required=True)
    p.add_argument('--preflight', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('evidence/league-comparator-26-oracle.json.gz'))
    a = p.parse_args()
    generate(a.binary, a.exports, a.preflight, a.output)
