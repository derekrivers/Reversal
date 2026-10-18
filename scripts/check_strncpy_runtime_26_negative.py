#!/usr/bin/env python3
"""Exercise R26-B specimen/native gates and retained oracle/model comparisons."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from extract_strncpy_runtime_26 import extract, need, sha, ENTRY


def rejected(binary, exports, preflight, fragment):
    try:
        extract(binary, exports, preflight)
    except ValueError as exc:
        need(fragment in str(exc), 'unexpected rejection: '+str(exc))
        return str(exc)
    raise ValueError('mutation incorrectly accepted: '+fragment)


def run(binary, exports, preflight, node):
    static = extract(binary, exports, preflight)
    receipt = {'schema_version': 1, 'unit': 'R26-B', 'optimized_python_safe': True,
               'integrity_rejections': {}, 'model_comparison_rejections': {}}
    with tempfile.TemporaryDirectory(prefix='cm0102-strncpy-negative-') as directory:
        base = Path(directory)
        changed_binary = base/'changed.exe'
        data = bytearray(binary.read_bytes())
        data[int(static['file_offset'], 16)+(0x946768-ENTRY)] ^= 1
        changed_binary.write_bytes(data)
        receipt['integrity_rejections']['specimen_byte'] = rejected(
            changed_binary, exports, preflight, 'pinned specimen mismatch')
        changed_exports = base/'exports'
        shutil.copytree(exports, changed_exports)
        asm = changed_exports/'009466d0.asm'
        text = asm.read_text(encoding='utf-8')
        need('MOV EAX,dword ptr [ESI]' in text, 'native mutation operand absent')
        asm.write_text(text.replace('MOV EAX,dword ptr [ESI]', 'MOV EAX,word ptr [ESI]', 1),
                       encoding='utf-8')
        receipt['integrity_rejections']['native_read_width'] = rejected(
            binary, changed_exports, preflight, 'native export mismatch')
        changed_preflight = base/'preflight.json'
        text = preflight.read_text(encoding='utf-8')
        need('"function_name": "_strncpy"' in text, 'exact-old name absent')
        changed_preflight.write_text(text.replace('"function_name": "_strncpy"',
                                     '"function_name": "_strncpy_changed"', 1), encoding='utf-8')
        receipt['integrity_rejections']['existing_name'] = rejected(
            binary, exports, changed_preflight, 'native manifest/preflight SHA-256 mismatch')
        text = preflight.read_text(encoding='utf-8')
        need('Library Function - Single Match' in text, 'exact-old comment absent')
        changed_preflight.write_text(text.replace('Library Function - Single Match',
                                                  'Changed library comment', 1), encoding='utf-8')
        receipt['integrity_rejections']['existing_comment'] = rejected(
            binary, exports, changed_preflight, 'native manifest/preflight SHA-256 mismatch')

        checker = Path('reconstruction/check-strncpy-runtime-26.ts')
        oracle = Path('evidence/strncpy-runtime-26-oracle.json.gz')
        good = subprocess.run([str(node), str(checker), str(oracle)], capture_output=True, text=True)
        need(good.returncode == 0, 'positive checker failed: '+good.stderr)
        for kind in ('output', 'register', 'stack', 'return', 'read', 'write-width'):
            bad = subprocess.run([str(node), str(checker), str(oracle), '--mutate-'+kind],
                                 capture_output=True, text=True)
            need(bad.returncode != 0 and 'original-instruction mismatch at case' in bad.stderr,
                 'model mutation was not rejected: '+kind)
            receipt['model_comparison_rejections'][kind] = 'original-instruction mismatch'
        changed_oracle = base/'oracle.json.gz'
        data = bytearray(oracle.read_bytes())
        data[-12] ^= 1
        changed_oracle.write_bytes(data)
        bad = subprocess.run([str(node), str(checker), str(changed_oracle)], capture_output=True, text=True)
        need(bad.returncode != 0 and 'original-instruction oracle SHA-256 mismatch' in bad.stderr,
             'changed oracle not rejected before decompression')
        receipt['integrity_rejections']['retained_oracle'] = 'oracle SHA-256 mismatch'
        receipt['positive_checker'] = good.stdout.strip()
        receipt['oracle_sha256'] = sha(oracle.read_bytes())
        receipt['node_version'] = subprocess.check_output([str(node), '--version'], text=True).strip()
    return receipt


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=Path)
    p.add_argument('--exports', type=Path, required=True)
    p.add_argument('--preflight', type=Path, required=True)
    p.add_argument('--node', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('evidence/strncpy-runtime-26-negative.json'))
    a = p.parse_args()
    result = run(a.binary, a.exports, a.preflight, a.node)
    a.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8', newline='\n')
    print('R26-B: five integrity mutations and six model mutations rejected; positive and eight admission checks pass')
