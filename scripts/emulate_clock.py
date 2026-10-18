#!/usr/bin/env python3
"""Exhaustive signed16 clock-conversion oracle from an original x86 code slice.

Only 0x006d70c4..0x006d70ef is executed. This is a basic-block calculation,
not execution of the surrounding commentary routine or a complete match.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import unicorn
from unicorn.x86_const import UC_X86_REG_EDI,UC_X86_REG_EDX,UC_X86_REG_EIP
from emulate_random import Oracle,EXPECTED

START=0x006d70c4
END=0x006d70f0
CONTEXT=0x04000000
MODES=[0,1,255]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    if args.output.exists():parser.error('choose a new output directory')
    oracle=Oracle(args.binary.read_bytes(),code_ranges=[(START,END)])
    oracle.uc.mem_map(CONTEXT,0x10000)
    oracle.uc.reg_write(UC_X86_REG_EDI,CONTEXT)
    outputs=bytearray()
    for mode in MODES:
        oracle.uc.mem_write(CONTEXT,bytes([mode]))
        for raw in range(65536):
            oracle.uc.mem_write(CONTEXT+0x8ed0,struct.pack('<H',raw))
            oracle.uc.reg_write(UC_X86_REG_EDX,0x76543210)
            oracle.uc.emu_start(START,END,timeout=100000,count=32)
            if oracle.uc.reg_read(UC_X86_REG_EIP)!=END:raise RuntimeError('slice did not reach its boundary')
            outputs.append(oracle.uc.reg_read(UC_X86_REG_EDX)&255)
    args.output.mkdir(parents=True)
    (args.output/'clock-oracle.bin').write_bytes(outputs)
    metadata={'sha256':EXPECTED,'oracle':'original x86 basic-block emulation','emulator':'unicorn '+unicorn.__version__,
              'slice_start':hex(START),'slice_end_exclusive':hex(END),'result':'DL low byte at slice exit',
              'modes':MODES,'clock_raw_values_per_mode':65536,'cases':len(outputs),'executed_instructions':oracle.instructions,
              'oracle_sha256':hashlib.sha256(outputs).hexdigest(),
              'layout':'for each listed mode, output bytes indexed by raw uint16 clock (0..65535)',
              'supported_rule':'mode0: uint8(trunc(signed16(clock)/11)); nonzero mode: clock low byte',
              'limitations':['Synthetic context; no full-game run','Executes only timestamp conversion, not surrounding event creation',
                             'All signed16 clock bit patterns tested; nonzero modes1 and255 tested, not all 255 nonzero byte values']}
    (args.output/'clock-oracle.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps(metadata,indent=2))

if __name__=='__main__':main()
