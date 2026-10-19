#!/usr/bin/env python3
"""Check that R28-B public evidence contains compact synthetic observations only."""
import argparse
import gzip
import json
from pathlib import Path


def check(sites_path, oracle_path):
    sites=json.loads(sites_path.read_text())
    oracle=json.loads(gzip.decompress(oracle_path.read_bytes()))
    if set(sites)!={"work_unit","specimen_sha256","checkpoint_archive_sha256","export_manifest_sha256",
                   "preflight_sha256","method","functions"}:
        raise ValueError("unexpected site evidence fields")
    allowed_site={"entry_va","file_offset","body_bytes","body_sha256","native_export_sha256",
                  "instruction_count","matched_native_instructions","reachable_instruction_starts",
                  "edges","return_sites","calls","memory_operands"}
    if len(sites["functions"])!=2 or any(set(site)!=allowed_site for site in sites["functions"]):
        raise ValueError("unexpected site details")
    if set(oracle)!={"work_unit","specimen_sha256","sites_sha256","domain","cases_count",
                    "executed_instruction_steps","covered_instruction_starts","covered_edges","cases"}:
        raise ValueError("unexpected oracle fields")
    if oracle["cases_count"]!=256 or len(oracle["cases"])!=256 or len(oracle_path.read_bytes())>250000:
        raise ValueError("unexpected oracle size or count")
    for row in oracle["cases"]:
        if set(row)!={"input","initial","final","trace","events","memory_sha256"} or \
                set(row["input"])!={"seed","offset","receiver"} or \
                not 0<=row["input"]["seed"]<16 or row["input"]["receiver"]<0x200000:
            raise ValueError("non-synthetic oracle row")
        if len(row["trace"])!=7 or len(row["events"])!=5 or len(row["memory_sha256"])!=2:
            raise ValueError("unexpected retained original data")
    return {"work_unit":"R28-B","status":"passed","synthetic_cases":256,
            "retained_memory":"two SHA-256 digests per case; no memory pages or PE bytes",
            "oracle_compressed_bytes":len(oracle_path.read_bytes())}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("sites","oracle","output"):
        parser.add_argument(name,type=Path)
    args=parser.parse_args()
    args.output.write_text(json.dumps(check(args.sites,args.oracle),indent=2)+"\n",encoding="utf-8",newline="\n")
