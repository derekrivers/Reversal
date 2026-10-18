#!/usr/bin/env python3
"""Generate an oracle from original x86 RNG instructions in a bounded emulator.

No Windows process or full game is launched. Only three admitted instruction
ranges execute; synthetic RNG state and the original fixed table are supplied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EIP

EXPECTED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
TABLE = 0x00aa2454
TABLE_END = 0x00ad4130
WORDS = (TABLE_END-TABLE)//4+1
CURSOR = 0x00de1f60
OFFSET = 0x00de1f5c
LIMIT = 0x00de2798
SEED = 0x00ad6c30
STOP = 0x03000000
STACK = 0x02000000

class Oracle:
    def __init__(self, data, code_ranges=None):
        if hashlib.sha256(data).hexdigest() != EXPECTED:
            raise ValueError("unexpected game SHA-256")
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        optional = pe+24
        base = struct.unpack_from("<I", data, optional+28)[0]
        image_size = struct.unpack_from("<I", data, optional+56)[0]
        header_size = struct.unpack_from("<I", data, optional+60)[0]
        count = struct.unpack_from("<H", data, pe+6)[0]
        optional_size = struct.unpack_from("<H", data, pe+20)[0]
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(base, (image_size+4095)&~4095)
        self.uc.mem_write(base, data[:header_size])
        for index in range(count):
            position = optional+optional_size+40*index
            virtual, rva, size, raw = struct.unpack_from("<IIII", data, position+8)
            if size:
                self.uc.mem_write(base+rva, data[raw:raw+size])
        self.uc.mem_map(STACK, 0x10000)
        self.uc.mem_map(STOP, 0x1000)
        self.instructions = 0
        if code_ranges is None:
            code_ranges=[(0x0090cfc0,0x0090d09d),(0x009469fa,0x00946a22)]
        def admitted(uc, address, size, unused):
            allowed = any(start <= address < end for start,end in code_ranges)
            if not allowed:
                raise RuntimeError(f"instruction outside admitted RNG ranges: {address:#x}")
            self.instructions += 1
        self.uc.hook_add(UC_HOOK_CODE, admitted)
        self.table_bytes = bytes(self.uc.mem_read(TABLE, WORDS*4))

    def put(self, address, value):
        self.uc.mem_write(address, struct.pack("<I", value&0xffffffff))

    def get(self, address):
        return struct.unpack("<I", self.uc.mem_read(address,4))[0]

    def call(self, address, argument=None):
        sp = STACK+0x8000
        self.put(sp, STOP)
        if argument is not None:
            self.put(sp+4,argument)
        self.uc.reg_write(UC_X86_REG_ESP,sp)
        self.uc.reg_write(UC_X86_REG_EAX,0)
        self.uc.emu_start(address,STOP,timeout=100000,count=5000)
        if self.uc.reg_read(UC_X86_REG_EIP) != STOP:
            raise RuntimeError("RNG did not return within the instruction/time budget")
        return self.uc.reg_read(UC_X86_REG_EAX)&0xffffffff

    def set_state(self, state):
        self.put(CURSOR,TABLE+state["cursorIndex"]*4)
        self.put(LIMIT,TABLE_END)
        self.put(OFFSET,state["offset"])
        self.put(SEED,state["crtState"])

    def state(self):
        return {"cursorIndex":(self.get(CURSOR)-TABLE)//4,"offset":self.get(OFFSET),"crtState":self.get(SEED)}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary",type=Path)
    parser.add_argument("output",type=Path,help="new output directory")
    parser.add_argument("--synthetic-table",action="store_true",help="replace fixed game data with a deterministic synthetic table for public regression fixtures")
    args=parser.parse_args()
    if args.output.exists():
        parser.error("choose a new output directory")
    oracle=Oracle(args.binary.read_bytes())
    table_origin="fixed table from pinned executable"
    if args.synthetic_table:
        synthetic_state=0x10203968
        synthetic_words=[]
        for _ in range(WORDS):
            synthetic_state=(synthetic_state*214013+2531011)&0xffffffff
            synthetic_words.append((synthetic_state>>16)&32767)
        oracle.table_bytes=struct.pack(f"<{WORDS}I",*synthetic_words)
        oracle.uc.mem_write(TABLE,oracle.table_bytes)
        table_origin="synthetic fixture: LCG seed0x10203968, state=state*214013+2531011 mod2^32, word=(state>>16)&32767"
    args.output.mkdir(parents=True)
    (args.output/"random-table.bin").write_bytes(oracle.table_bytes)
    rng=random.Random(0x010203968)
    seeds=[0,1,2,0x7fffffff,0x80000000,0xffffffff]+[rng.getrandbits(32) for _ in range(26)]
    crt=[]
    for seed in seeds:
        oracle.put(SEED,seed)
        outputs=[]
        for _ in range(32):
            value=oracle.call(0x00946a04)
            outputs.append({"value":value,"state":oracle.get(SEED)})
        crt.append({"seed":seed,"steps":outputs})
    bounds=[-65535,-32768,-200,-30,-7,-2,-1,0,1,2,3,4,7,15,20,25,30,200,7000,32768,65535]
    states=[]
    for cursor in [-1,0,1,12345,WORDS-2,WORDS-1]:
        for offset in [0,32767,65535]:
            states.append({"cursorIndex":cursor,"offset":offset,"crtState":rng.getrandbits(32)})
    for _ in range(80):
        states.append({"cursorIndex":rng.randrange(WORDS),"offset":rng.randrange(65536),"crtState":rng.getrandbits(32)})
    cases=[]
    for initial in states:
        for bound in bounds:
            oracle.set_state(initial)
            value=oracle.call(0x0090cfc0,bound)
            signed=value if value < 0x80000000 else value-0x100000000
            cases.append({"bound":bound,"initial":initial,"value":signed,"final":oracle.state()})
    # Preserve a sequential stream across wrap, with zero-bound calls mixed in.
    oracle.set_state({"cursorIndex":WORDS-3,"offset":12345,"crtState":1})
    chain=[]
    for i in range(512):
        bound=bounds[i%len(bounds)]
        initial=oracle.state()
        value=oracle.call(0x0090cfc0,bound)
        signed=value if value < 0x80000000 else value-0x100000000
        chain.append({"bound":bound,"initial":initial,"value":signed,"final":oracle.state()})
    table=struct.unpack(f"<{WORDS}I",oracle.table_bytes)
    result={"sha256":EXPECTED,"oracle":"original x86 instruction emulation","emulator":"unicorn "+unicorn.__version__,
            "table":{"origin":table_origin,"va":hex(TABLE),"last_va":hex(TABLE_END),"words":WORDS,"bytes":len(oracle.table_bytes),"min":min(table),"max":max(table),"sha256":hashlib.sha256(oracle.table_bytes).hexdigest()},
            "crt":crt,"bounded_cases":cases,"sequential_cases":chain,"executed_instructions":oracle.instructions,
            "coverage":{"crt_steps":sum(len(x['steps']) for x in crt),"bounded_calls":len(cases)+len(chain),"argument_domain":"signed integer -65535 through 65535; sampled bounds and synthetic states","zero_bound":"included; must not consume state","table_wrap":"included; must advance CRT and offset"},
            "limitations":["Synthetic state; no original full-game run or match equivalence test", "Large-argument x87 branch is deliberately excluded", "No test of operating-system-time seeding or saved-game RNG restoration", "No claim that a game run uses only these random sources"]}
    (args.output/"x86-oracle.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"coverage":result['coverage'],"table":result['table'],"instructions":oracle.instructions},indent=2))

if __name__=="__main__":
    main()
