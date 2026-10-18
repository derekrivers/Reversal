#!/usr/bin/env python3
"""Acquire the exact community-hosted specimen used in this investigation."""
import argparse
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile

COMMIT = "69cdaedd611450f33fb73fa2f41f14f5039f3918"
URL = f"https://raw.githubusercontent.com/nckstwrt/CM0102-Starter-Kit/{COMMIT}/external/Exes.zip"
EXPECTED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new path")
    with urllib.request.urlopen(URL, timeout=120) as response:
        archive = response.read()
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        data = package.read("cm0102.exe")
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise SystemExit(f"Specimen SHA-256 mismatch: {digest}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"Saved {len(data)} bytes: {args.output}\nSHA-256 {digest}")
    print("Pinned 3.9.68 specimen; archived updater comparison is recorded in evidence/official-patch-comparison.json.")

if __name__ == "__main__":
    main()
