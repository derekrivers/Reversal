#!/usr/bin/env python3
"""Run complete pinned R21-A instructions on synthetic disjoint memory.

python emulate_match_microhelpers_21.py EXE EXPORTS PREFLIGHT NEW_OUTPUT_DIR
Dependencies: capstone==5.0.7, unicorn==2.1.4. No original bytes are emitted.
All integrity checks remain active under Python -O.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn import x86_const as x
from extract_match_microhelpers_21 import extract, PINNED

SP, STOP, RECEIVER, MATCH = 0x20000800, 0x30000000, 0x10000000, 0x11000000
REGS = {'eax': x.UC_X86_REG_EAX, 'edx': x.UC_X86_REG_EDX, 'eflags': x.UC_X86_REG_EFLAGS}
PRESERVED = {x.UC_X86_REG_EBX: 0x12345678, x.UC_X86_REG_EBP: 0x87654321,
             x.UC_X86_REG_ESI: 0x10203968, x.UC_X86_REG_EDI: 0xfedcba98}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def rows():
    result = []
    for a in range(256):
        for b in range(256):
            result.append([1, RECEIVER + (b % 4)*13, MATCH, a, b, len(result)])
    for b in range(256):
        result.append([2, RECEIVER + (b % 4)*13, MATCH, 255-b, b, len(result)])
    # Last touched byte ends exactly at a mapped-page edge, with unaligned bases.
    for receiver in [RECEIVER, RECEIVER+1, RECEIVER+0xe5e]:
        for match in [MATCH, MATCH+1, MATCH+0xa7a]:
            for seed in [0, 1, 255, 0xffff]:
                result.append([0, receiver, match, 0xa5, 0, seed])
    for kind in [1, 2]:
        for arg in [0, 0xff, 0x100, 0x7fffffff, 0x80000000, 0xffffffff]:
            result.append([kind, RECEIVER+0xfd4, MATCH, 255, arg, len(result)])
    return result

def registers(seed):
    return {'eax': (0xa1230000+seed*0x10201)&0xffffffff,
            'edx': (0xb2340000+seed*0x20103)&0xffffffff,
            'eflags': [0x202, 0xad7, 0x246, 0x293][seed % 4]}

def regions(row):
    kind, receiver, match, initial, argument, seed = row
    bases = [RECEIVER, MATCH, 0x20000000] if kind == 0 else [RECEIVER, 0x20000000]
    result = {base: bytearray(bytes((i*29+(base>>12)*7+seed*3+0x53)&255 for i in range(256))
                              * (256 if base == MATCH else 16)) for base in bases}
    def put(address, size, value):
        for base, data in result.items():
            if base <= address and address+size <= base+len(data):
                data[address-base:address-base+size] = value.to_bytes(size, 'little')
                return
        raise ValueError('fixture write outside admitted memory')
    put(receiver+0x2b, 1, initial)
    if kind == 0:
        put(receiver+0x19e, 4, match)
    put(SP, 4, STOP)
    put(SP+4, 4, argument)
    return result

def encode_accesses(accesses):
    return b''.join(struct.pack('<III', *access) for access in accesses)

def generate(specimen, exports, preflight, output):
    require(unicorn.__version__ == '2.1.4', 'requires unicorn==2.1.4')
    static = extract(specimen, exports, preflight)
    binary = specimen.read_bytes()
    machines, logs = [], {'reads': [], 'writes': [], 'trace': []}
    starts = []
    for fn in static['functions']:
        entry = int(fn['entry_va'], 16)
        offset = int(fn['entry_file_offset'], 16)
        body = binary[offset:offset+fn['body_bytes']]
        instruction_starts = [int(line.split()[0], 16) for line in (exports/(fn['entry_va']+'.asm')).read_text().splitlines()]
        starts.append(instruction_starts)
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(entry&~4095, 4096)
        uc.mem_write(entry, body)
        uc.mem_protect(entry&~4095, 4096, UC_PROT_READ|UC_PROT_EXEC)
        uc.mem_map(STOP, 4096, UC_PROT_READ|UC_PROT_EXEC)
        uc.mem_map(RECEIVER, 4096)
        uc.mem_map(0x20000000, 4096)
        if len(machines) == 0:
            uc.mem_map(MATCH, 0x10000)
        def code(uc, address, size, unused, admitted=set(instruction_starts)):
            require(address in admitted, 'execution escaped complete body')
            logs['trace'].append(address)
        def read(uc, access, address, size, value, unused):
            logs['reads'].append([address, size, 0])
        def write(uc, access, address, size, value, unused):
            logs['writes'].append([address, size, value&((1 << (size*8))-1)])
        uc.hook_add(UC_HOOK_CODE, code)
        uc.hook_add(UC_HOOK_MEM_READ, read)
        uc.hook_add(UC_HOOK_MEM_WRITE, write)
        machines.append(uc)
    hashes = {name: hashlib.sha256() for name in ['before_memory', 'after_memory', 'reads', 'writes']}
    reached = [set(), set(), set()]
    records = bytearray()
    inputs = rows()
    for index, row in enumerate(inputs):
        kind, receiver, match, initial, argument, seed = row
        uc, fn = machines[kind], static['functions'][kind]
        initial_regions = regions(row)
        before = b''.join(initial_regions.values())
        for base, data in initial_regions.items():
            uc.mem_write(base, bytes(data))
        for register, value in PRESERVED.items():
            uc.reg_write(register, value)
        for name, value in registers(seed).items():
            uc.reg_write(REGS[name], value)
        uc.reg_write(x.UC_X86_REG_ECX, receiver)
        uc.reg_write(x.UC_X86_REG_ESP, SP)
        for log in logs.values():
            log.clear()
        uc.emu_start(int(fn['entry_va'], 16), STOP, count=20)
        require(uc.reg_read(x.UC_X86_REG_EIP) == STOP, 'did not return')
        require(uc.reg_read(x.UC_X86_REG_ESP) == SP+(4 if kind == 0 else 8), 'incorrect return stack cleanup')
        require(uc.reg_read(x.UC_X86_REG_ECX) == receiver, 'receiver not preserved')
        require(all(uc.reg_read(reg) == value for reg, value in PRESERVED.items()), 'callee-saved register changed')
        require(logs['trace'] == starts[kind], 'not every original instruction executed exactly once')
        reached[kind].update(logs['trace'])
        # Validate every byte, including neighbours and stack, against the logged writes.
        expected = {base: bytearray(data) for base, data in initial_regions.items()}
        for address, size, value in logs['writes']:
            targets = [base for base, data in expected.items() if base <= address and address+size <= base+len(data)]
            require(len(targets) == 1, 'write outside admitted memory')
            base = targets[0]
            expected[base][address-base:address-base+size] = value.to_bytes(size, 'little')
        after = b''.join(bytes(uc.mem_read(base, len(data))) for base, data in initial_regions.items())
        require(after == b''.join(expected.values()), 'unlogged synthetic memory modification')
        hashes['before_memory'].update(before)
        hashes['after_memory'].update(after)
        for name in ['reads', 'writes']:
            hashes[name].update(struct.pack('<I', len(logs[name])))
            hashes[name].update(encode_accesses(logs[name]))
        records.extend(struct.pack('<III', *(uc.reg_read(REGS[name]) for name in ['eax', 'edx', 'eflags'])))
    require([len(x) for x in reached] == [12, 5, 3], 'incomplete original instruction coverage')
    require(not output.exists(), 'output directory must be new')
    output.mkdir(parents=True)
    (output/'registers.bin').write_bytes(records)
    result = {'schema': 1, 'specimen_sha256': PINNED, 'emulator': 'Unicorn 2.1.4',
              'python': platform.python_version(), 'origin': 'synthetic disjoint memory; original complete instructions',
              'cases': len(inputs), 'counts': [sum(r[0] == kind for r in inputs) for kind in range(3)],
              'record': 'little-endian uint32 EAX, EDX, EFLAGS in deterministic rows() order',
              'registers_sha256': digest(records), 'whole_memory_and_access_sha256': {name: h.hexdigest() for name, h in hashes.items()},
              'original_instructions_reached': [len(x) for x in reached],
              'abi': 'All cases preserve ECX/EBX/EBP/ESI/EDI; RET adds 4 to ESP, RET4 adds 8; EIP reaches sentinel',
              'functions': static['functions'],
              'limitations': 'Stable nonaliasing mapped receiver/match/stack only; no invalid pointer, aliasing, concurrent state, caller reachability or connected match equivalence'}
    (output/'oracle.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'cases': len(inputs), 'counts': result['counts'], 'registers_sha256': result['registers_sha256']}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ['specimen', 'exports', 'preflight', 'output']:
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    generate(args.specimen, args.exports, args.preflight, args.output)
