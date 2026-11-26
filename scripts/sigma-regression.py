#!/usr/bin/env python3
"""Runs every SigmaHQ regression sample (regression_data/**/info.yml) through
`forhunt sigma` with its rule and compares the match count (D-067).

Usage: scripts/sigma-regression.py SIGMAHQ_CHECKOUT path/to/forhunt  (needs PyYAML)
"""
import yaml, glob, subprocess, sys, os, json, collections
root, fh = sys.argv[1], sys.argv[2]
ids = {}
for f in glob.glob(root + '/rules*/**/*.yml', recursive=True):
    try: d = yaml.safe_load(open(f))
    except Exception: continue
    if isinstance(d, dict) and 'id' in d: ids[d['id']] = f
res = collections.Counter(); bad = []
for info in sorted(glob.glob(root + '/regression_data/**/info.yml', recursive=True)):
    i = yaml.safe_load(open(info))
    rid = i['rule_metadata'][0]['id']
    for t in i.get('regression_tests_info', []):
        if t.get('type') != 'evtx': continue
        rule = ids.get(rid)
        if not rule: res['rule missing'] += 1; continue
        evtx = os.path.join(root, t['path'])
        p = subprocess.run([fh, 'sigma', evtx, '-R', rule, '--min-level', 'informational', '--deprecated', '-F', 'jsonl', '-n', '0', '-q'], capture_output=True, text=True)
        if p.returncode != 0:
            why = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else '?'
            res['not run'] += 1; bad.append(('NOTRUN', rule, why)); continue
        n = len([l for l in p.stdout.splitlines() if l.strip()])
        want = t.get('match_count')
        if want is None: res['no count'] += 1; continue
        if n == want: res['ok'] += 1
        else: res['mismatch'] += 1; bad.append(('MISMATCH', rule, f'got {n} want {want}'))
print(dict(res))
for b in bad: print(*b, sep=' | ')
