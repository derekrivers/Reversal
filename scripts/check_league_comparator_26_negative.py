#!/usr/bin/env python3
"""Reject R26-C specimen/native/preflight/oracle and behavioral mutations."""
import argparse
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from extract_league_comparator_26 import extract, need, ENTRY


def rejected(binary, exports, preflight, fragment):
    try:
        extract(binary, exports, preflight)
    except ValueError as exc:
        need(fragment in str(exc), 'unexpected integrity rejection: '+str(exc))
        return str(exc)
    raise ValueError('mutation incorrectly accepted: '+fragment)


def run(binary, exports, preflight, node):
    original = extract(binary, exports, preflight)
    version = subprocess.run([str(node), '--version'], capture_output=True, text=True, check=True).stdout.strip()
    need(version.startswith('v24.'), 'negative TypeScript validation requires Node24')
    results = {'schema_version': 1, 'unit': 'R26-C', 'optimized_python_safe': True, 'node_version': version}
    with tempfile.TemporaryDirectory(prefix='cm0102-league-negative-') as directory:
        base = Path(directory)
        for label, offset in [('instruction_byte_mutation', int(original['file_offset'], 16)+(0x68350e-ENTRY)),
                              ('switch_table_byte_mutation', int(original['switch_table']['file_offset'], 16))]:
            changed = bytearray(binary.read_bytes())
            changed[offset] ^= 1
            target = base/(label+'.exe')
            target.write_bytes(changed)
            results[label] = rejected(target, exports, preflight, 'pinned specimen mismatch')
        changed_exports = base/'exports'
        shutil.copytree(exports, changed_exports)
        target = changed_exports/'006834f0.asm'
        text = target.read_text(encoding='utf-8')
        need('MOV CX,word ptr [ESI + 0x19]' in text, 'native width mutation operand absent')
        target.write_text(text.replace('MOV CX,word ptr [ESI + 0x19]', 'MOV CX,byte ptr [ESI + 0x19]', 1), encoding='utf-8')
        results['native_width_mutation'] = rejected(binary, changed_exports, preflight, 'native export mismatch')
        target = base/'preflight.json'
        text = preflight.read_text(encoding='utf-8')
        need('FUN_006834f0' in text, 'exact-old mutation operand absent')
        target.write_text(text.replace('FUN_006834f0', 'FUN_006834f1', 1), encoding='utf-8')
        results['exact_old_name_mutation'] = rejected(binary, exports, target, 'native manifest/preflight SHA-256 mismatch')
        oracle = Path('evidence/league-comparator-26-oracle.json.gz')
        target = base/'oracle.json.gz'
        text = gzip.decompress(oracle.read_bytes()).decode('utf-8')
        need('"cases_count":840' in text, 'oracle mutation field absent')
        target.write_bytes(gzip.compress(text.replace('"cases_count":840', '"cases_count":841', 1).encode('utf-8'),
                                         compresslevel=9, mtime=0))
        checker = 'reconstruction/check-league-comparator-26.ts'
        for label, arguments, error in [
            ('oracle_metadata_mutation', [str(target)], 'oracle SHA-256 mismatch'),
            ('return_mutation', [str(oracle), '--mutate-result'], 'original-instruction mismatch at case 0'),
            ('ordered_read_mutation', [str(oracle), '--mutate-read-order'], 'original-instruction mismatch at case 1')]:
            result = subprocess.run([str(node), checker, *arguments], capture_output=True, text=True)
            need(result.returncode != 0 and error in result.stderr, 'mutation incorrectly accepted: '+label)
            results[label] = error
    return results


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=Path)
    p.add_argument('--exports', type=Path, required=True)
    p.add_argument('--preflight', type=Path, required=True)
    p.add_argument('--node', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('evidence/league-comparator-26-negative.json'))
    a = p.parse_args()
    result = run(a.binary, a.exports, a.preflight, a.node)
    a.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8', newline='\n')
    print('R26-C seven specimen/native/preflight/oracle/behavior mutations rejected')
