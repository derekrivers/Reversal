#!/usr/bin/env python3
"""Independently constrain retained R29-C oracle to the public synthetic schedule."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

SITE = "7df90b7f1fa9cbe246e85d6b2d829098c7f7ddaf9350a2801ca88d8ec2aa820b"
ORACLE = "61ad24b654668d3b9a7f9c797fc5a7315d9d8068c09316b9834329b21553b3eb"
OFFSETS = (0,1,2,3,7,15,31,63,127,255,511,1023,1535,2047,3071,4082)
REGS = {"eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate(raw, oracle):
    if sha(raw) != SITE or oracle.get("sites_sha256") != SITE or oracle.get("cases_count") != 1024:
        raise ValueError("provenance/count mismatch")
    if set(oracle) != {"work_unit","specimen_sha256","sites_sha256","domain","cases_count",
                       "executed_instruction_steps","covered_instruction_starts","covered_edges","cases"}:
        raise ValueError("oracle schema mismatch")
    if len(oracle["cases"]) != 1024 or oracle["executed_instruction_steps"] != 5120:
        raise ValueError("oracle coverage count mismatch")
    for index, row in enumerate(oracle["cases"]):
        mode, seed, offset = index//256, (index//16)%16, OFFSETS[index%16]
        receiver = 0x200000 + offset
        cursor = 0 if mode == 0 else (receiver if mode == 1 else 0x200800+((seed*31+offset)%0x7f0))
        if set(row) != {"input","initial","final","trace","events","memory_sha256"} or \
                row["input"] != {"mode":mode,"seed":seed,"offset":offset,"receiver":receiver,"cursor":cursor}:
            raise ValueError("synthetic row/schema mismatch")
        if set(row["initial"]) != REGS or set(row["final"]) != REGS:
            raise ValueError("register schema mismatch")
        data = bytearray((i*29+seed*17+mode*11+3)&255 for i in range(4096))
        stack = bytearray((i*19+seed*13+5)&255 for i in range(4096))
        data[offset+10:offset+14] = cursor.to_bytes(4,"little")
        if cursor and mode >= 2:
            value = (seed*0x10203041+mode*0x80000001+offset)&0xffffffff
            data[cursor-0x200000:cursor-0x200000+4] = value.to_bytes(4,"little")
        stack[0x800:0x804] = (0x700000).to_bytes(4,"little")
        expected_events = [["read",f"{receiver+10:08x}",4]]
        if cursor:
            expected_events.append(["read",f"{cursor:08x}",4])
        expected_events.append(["read","00400800",4])
        expected_trace = ["0068d2e0","0068d2e3","0068d2e5"] + \
            (["0068d2e7","0068d2e9"] if cursor else ["0068d2ea","0068d2ec"])
        if row["events"] != expected_events or row["trace"] != expected_trace:
            raise ValueError("ordered synthetic evidence mismatch")
        if row["memory_sha256"] != [sha(data),sha(stack)]:
            raise ValueError("full synthetic memory mismatch")


def run(sites_path, oracle_path):
    sites_raw, payload = sites_path.read_bytes(), oracle_path.read_bytes()
    if len(payload) > 1000000 or sha(payload) != ORACLE:
        raise ValueError("retained oracle mismatch")
    oracle = json.loads(payload)
    if payload != (json.dumps(oracle,separators=(",", ":"))+"\n").encode():
        raise ValueError("noncanonical oracle JSON")
    validate(sites_raw, oracle)
    mutations=[]
    for label, change in (
        ("nested raw page",lambda row: row["initial"].update(page="00"*4096)),
        ("wrong offset",lambda row: row["input"].update(offset=17)),
        ("hidden event",lambda row: row["events"].append(["page","00"*4096])),
        ("wrong memory digest",lambda row: row["memory_sha256"].__setitem__(0,"0"*64))):
        changed=copy.deepcopy(oracle)
        change(changed["cases"][0])
        try:
            validate(sites_raw,changed)
        except ValueError:
            mutations.append(label+" rejected")
        else:
            raise ValueError("privacy mutation admitted: "+label)
    return {"unit":"R29-C","status":"passed","synthetic_cases":1024,
            "retained_memory":"two full-page SHA-256 digests per case; no page bytes or PE instructions",
            "oracle_bytes":len(payload),"negative_mutations":mutations}


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for field in ("sites","oracle","output"):
        p.add_argument(field,type=Path)
    a=p.parse_args()
    a.output.write_text(json.dumps(run(a.sites,a.oracle),indent=2)+"\n",encoding="utf-8",newline="\n")
