#!/usr/bin/env python3
"""Execute only pinned original 0094fded bytes with synthetic memory (Unicorn2.1.4).

Usage: python emulate_descriptor_handle_20.py EXE NATIVE_ASM NEW_OUTPUT_DIRECTORY
No raw code, original runtime pages or private paths are written to the oracle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import sys

import unicorn
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE,
                     UC_PROT_READ, UC_PROT_EXEC)
from unicorn import x86_const as x

SPECIMEN = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
BODY_HASH = 'bc15fa380be7e1320498ba101d1f41e7bf28ecdfa284dfc1438c4a44ff0cc1c9'
ASM_HASH = 'f5b8380d00d50539877ec35f2042aeb3cc0b93576608db635218395cbc85d533'
ENTRY, END, STOP, SP = 0x94fded, 0x94fe2a, 0x30000000, 0x20000800
BOUND, TABLE, ERR, DOSERR = 0xde43e0, 0xde42e0, 0xde2f8c, 0xde2f90
STARTS = [0x94fded, 0x94fdf1, 0x94fdf7, 0x94fdf9, 0x94fdfb, 0x94fdfe,
          0x94fe01, 0x94fe08, 0x94fe0d, 0x94fe10, 0x94fe12, 0x94fe14,
          0x94fe15, 0x94fe1c, 0x94fe26, 0x94fe29]
REGISTERS = {'ebx': x.UC_X86_REG_EBX, 'ebp': x.UC_X86_REG_EBP,
             'esi': x.UC_X86_REG_ESI, 'edi': x.UC_X86_REG_EDI, 'edx': x.UC_X86_REG_EDX}
SENTINELS = {name: 0x12340000 + index * 0x1111 for index, name in enumerate(REGISTERS)}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def load_original(binary, assembly):
    data = binary.read_bytes()
    require(digest(data) == SPECIMEN, 'unexpected specimen SHA-256')
    require(digest(assembly.read_bytes()) == ASM_HASH, 'unexpected native assembly SHA-256')
    require(len(data) == 7192576, 'unexpected specimen size')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    require(data[pe:pe+4] == b'PE\0\0', 'missing PE signature')
    require(struct.unpack_from('<H', data, pe+4)[0] == 0x14c, 'not x86')
    opt = pe + 24
    require(struct.unpack_from('<H', data, opt)[0] == 0x10b, 'not PE32')
    base = struct.unpack_from('<I', data, opt+28)[0]
    count = struct.unpack_from('<H', data, pe+6)[0]
    size = struct.unpack_from('<H', data, pe+20)[0]
    matches = []
    for i in range(count):
        position = opt + size + 40*i
        _, rva, raw_size, raw = struct.unpack_from('<IIII', data, position+8)
        if base+rva <= ENTRY and END <= base+rva+raw_size:
            offset = raw + ENTRY-base-rva
            matches.append((offset, data[offset:offset+END-ENTRY]))
    require(len(matches) == 1, 'body must belong to one raw-backed PE section')
    offset, body = matches[0]
    require(offset == 0x54fded and digest(body) == BODY_HASH, 'unexpected body extent/hash')
    native_starts = [int(line.split()[0], 16) for line in assembly.read_text().splitlines() if line.strip()]
    require(native_starts == STARTS, 'native instruction membership differs')
    return body

def cases():
    rows = []
    def add(label, descriptor, bound, flag=1, handle=0xabcdef01, page=0x10000000, fault=False):
        i = len(rows)
        rows.append([label, descriptor, bound, flag, handle, page,
                     (0xface0000+i*65537)&0xffffffff, (0xbeef0000+i*31337)&0xffffffff, fault])
    # Exhaust all flag bytes: bit zero alone controls the branch.
    for flag in range(256):
        add(f'flag-{flag:02x}', 33, 65, flag, (0x87654321+flag*0x10203)&0xffffffff)
    for descriptor in [0, 1, 30, 31, 32, 33, 63, 64, 2047]:
        for handle in [0, 1, 0x7fffffff, 0x80000000, 0xffffffff]:
            add(f'entry-{descriptor}-handle-{handle:08x}', descriptor, descriptor+1, 0x81, handle)
        add(f'bound-equal-{descriptor}', descriptor, descriptor, 0, page=0x40000000)
        add(f'closed-{descriptor}', descriptor, descriptor+1, 0xfe)
    for descriptor, bound in [(0, 0), (1, 0), (65, 64), (0xffffffff, 0xffffffff),
                              (0xffffffff, 0), (0x80000000, 0x7fffffff), (0xfffffffe, 1)]:
        add(f'unsigned-fail-{descriptor:08x}-{bound:08x}', descriptor, bound, page=0x40000000)
    for descriptor in [0x7fffffff, 0x80000000, 0x8000001f, 0xffffffde, 0xfffffffe]:
        add(f'high-index-{descriptor:08x}', descriptor, 0xffffffff, handle=descriptor)
        add(f'high-index-closed-{descriptor:08x}', descriptor, 0xffffffff, flag=0x80)
    for descriptor, page in [(31, 0x10000003), (31, 0x10000f10), (31, 0xffffff08), (0, 0)]:
        add(f'address-edge-{descriptor}-{page:08x}', descriptor, 64, handle=0x10203968, page=page)
    for flag in [0, 1]:
        add(f'already-zero-doserrno-flag-{flag}', 1, 2, flag)
        rows[-1][6:8] = [9, 0]
    # Access failure is separate from error9: the helper can fault before failure writes.
    add('unmapped-open-flag', 0, 1, page=0x40000000, fault=True)
    # page+31*8=0x0ffffffc is unmapped; entry+4=0x10000000 is mapped/open.
    add('unmapped-handle', 31, 32, page=0x0fffff04, fault=True)
    return rows

def setup_regions(row):
    _, descriptor, bound, flag, handle, page, err, doserr, fault = row
    signed = descriptor if descriptor < 0x80000000 else descriptor-0x100000000
    slot = (TABLE + (signed >> 5)*4)&0xffffffff
    bases = {0xde2000, 0xde3000, 0xde4000, 0x10000000, 0x10001000,
             0x11000000, 0x20000000, 0, 0xfffff000, slot&~4095}
    regions = {base: bytearray(((i*29 + (base>>12)*7 + 0x53)&255) for i in range(4096)) for base in sorted(bases)}
    def put(address, data):
        for i, value in enumerate(data):
            addr = (address+i)&0xffffffff
            regions[addr&~4095][addr&4095] = value
    def word(address, value):
        put(address, struct.pack('<I', value))
    # Fill the table neighbourhood with decoys; the exact slot is then selected.
    for address in range(TABLE-16, TABLE+256, 4):
        word(address, 0x11000000)
    word(BOUND, bound)
    word(slot, page)
    # On invalid bound cases slot can alias bound, but it must not change input.
    word(BOUND, bound)
    word(ERR, err)
    word(DOSERR, doserr)
    entry = (page+(descriptor&31)*8)&0xffffffff
    if not fault and descriptor < bound:
        word(entry, handle)
        put((entry+4)&0xffffffff, bytes([flag]))
    elif row[0] == 'unmapped-handle':
        put((entry+4)&0xffffffff, bytes([flag]))
    word(SP, STOP)
    word(SP+4, descriptor)
    return regions

def execute(body, row):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(ENTRY&~4095, 4096)
    uc.mem_write(ENTRY, body)
    uc.mem_protect(ENTRY&~4095, 4096, UC_PROT_READ|UC_PROT_EXEC)
    uc.mem_map(STOP, 4096, UC_PROT_READ|UC_PROT_EXEC)
    regions = setup_regions(row)
    for base, data in regions.items():
        uc.mem_map(base, 4096)
        uc.mem_write(base, bytes(data))
    uc.reg_write(x.UC_X86_REG_ESP, SP)
    uc.reg_write(x.UC_X86_REG_EAX, 0xdeadbeef)
    uc.reg_write(x.UC_X86_REG_ECX, 0xcafebabe)
    uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202 if row[1]&1 else 0x246)
    for name, register in REGISTERS.items():
        uc.reg_write(register, SENTINELS[name])
    trace, reads, writes = [], [], []
    def instruction(uc, address, size, unused):
        require(address in STARTS and address+size <= END, 'execution escaped admitted body')
        trace.append(address)
    def read(uc, access, address, size, value, unused):
        if address not in (SP, SP+4):
            reads.append([address, size])
    def write(uc, access, address, size, value, unused):
        writes.append([address, size, value&((1<<(size*8))-1)])
    def unmapped_read(uc, access, address, size, value, unused):
        reads.append([address, size])
        return False
    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_READ, read)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, unmapped_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    fault = None
    try:
        uc.emu_start(ENTRY, STOP, timeout=100000, count=32)
    except UcError as error:
        fault = error.errno
    require(bool(fault) == row[8], f'{row[0]}: unexpected execution/fault outcome')
    if fault:
        require(fault == unicorn.UC_ERR_READ_UNMAPPED, 'unexpected fault kind')
        require(not writes, 'fault wrote memory')
    else:
        require(uc.reg_read(x.UC_X86_REG_EIP) == STOP, 'did not return')
        require(uc.reg_read(x.UC_X86_REG_ESP) == SP+4, 'cdecl stack balance differs')
    preserved = {name: uc.reg_read(register) for name, register in REGISTERS.items()}
    require(preserved == SENTINELS, 'preserved register differs')
    # Every mapped synthetic byte is compared, including all unused descriptors,
    # stack/argument, table, guard bytes and error neighbours.
    before = b''.join(bytes(data) for data in regions.values())
    after = b''.join(bytes(uc.mem_read(base, 4096)) for base in regions)
    expected = {base: bytearray(data) for base, data in regions.items()}
    for address, size, value in writes:
        require(size == 4 and address in (DOSERR, ERR), 'unexpected direct memory write')
        struct.pack_into('<I', expected[address&~4095], address&4095, value)
    require(after == b''.join(bytes(data) for data in expected.values()), 'unlogged memory change')
    require(bytes(uc.mem_read(ENTRY, len(body))) == body, 'original code changed')
    def word(address):
        return struct.unpack('<I', uc.mem_read(address, 4))[0]
    # The separate READ_UNMAPPED hook retains the attempted read for TS matching.
    return {'eax': None if fault else uc.reg_read(x.UC_X86_REG_EAX),
            'errors': [word(ERR), word(DOSERR)], 'reads': reads, 'writes': writes,
            'before_sha256': digest(before), 'after_sha256': digest(after),
            'trace': [STARTS.index(address) for address in trace],
            'abi': {'esp': uc.reg_read(x.UC_X86_REG_ESP), 'preserved': preserved},
            'fault': 'read-unmapped' if fault else None}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('native_asm', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    require(unicorn.__version__ == '2.1.4', 'requires Unicorn 2.1.4')
    require(not args.output.exists(), 'choose a new output directory')
    body = load_original(args.binary, args.native_asm)
    inputs = cases()
    outputs = [execute(body, row) for row in inputs]
    reached = set(index for result in outputs for index in result['trace'])
    require(reached == set(range(16)), 'not every instruction executed')
    result = {'schema': 1, 'specimen_sha256': SPECIMEN,
              'oracle': 'original x86 instructions; synthetic descriptor memory only',
              'emulator': 'Unicorn '+unicorn.__version__,
              'body': {'entry_va': '0094fded', 'end_exclusive_va': '0094fe2a',
                       'file_offset': '0054fded', 'bytes': 61, 'instructions': 16,
                       'sha256': BODY_HASH, 'native_asm_sha256': ASM_HASH},
              'input_columns': ['label', 'descriptor', 'bound', 'flag', 'handle', 'page', 'errno', 'doserrno', 'fault'],
              'synthetic_memory': {'recipe': 'scripts/emulate_descriptor_handle_20.py setup_regions; mirrored in check-descriptor-handle.ts',
                                   'origin': 'synthetic byte/address pattern and synthetic descriptor/error fields'},
              'coverage': {'cases': len(inputs), 'faults': sum(row[8] for row in inputs),
                           'instructions_reached': len(reached), 'flag_bytes': 256,
                           'executed_instructions': sum(len(out['trace']) for out in outputs)},
              'inputs': inputs, 'outputs': outputs,
              'limitations': ['Stable nonaliasing synthetic runtime memory only; no concurrent mutation',
                              'Invalid readable storage can fault; no Windows SEH/OS behavior claimed',
                              'No descriptor lifecycle, seek wrapper, save format, or full-game equivalence']}
    args.output.mkdir(parents=True)
    (args.output/'oracle.json').write_text(json.dumps(result, separators=(',', ':'))+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'status': 'passed', 'coverage': result['coverage'],
                      'oracle_sha256': digest((args.output/'oracle.json').read_bytes()),
                      'python': platform.python_version()}))

if __name__ == '__main__':
    main()
