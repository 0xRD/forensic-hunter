#!/usr/bin/env python3
"""Extracts the sample events embedded in rules (`sample-evtx:` XML) to JSONL,
for `cargo run --release -p forhunt-core --example sigma_samples -- RULES OUT.jsonl`:
every loaded rule must match its own sample (D-063).

Usage: scripts/sigma-samples.py HAYABUSA_RULES_DIR OUT.jsonl  (needs PyYAML)
"""
import sys, glob, json, yaml, re
import xml.etree.ElementTree as ET
root = sys.argv[1]
out = open(sys.argv[2], 'w')
n = bad = 0
def strip(t): return t.split('}',1)[-1]
for f in sorted(glob.glob(root + '/**/*.yml', recursive=True)):
    try: d = yaml.safe_load(open(f, encoding='utf-8'))
    except Exception: continue
    if not isinstance(d, dict): continue
    x = d.get('sample-evtx') or d.get('hayabusa-sample-evtx')
    if not isinstance(x, str) or '<Event' not in x: continue
    x = x[x.index('<Event'):]
    x = x[:x.rindex('</Event>')+8] if '</Event>' in x else x
    try: e = ET.fromstring(x)
    except Exception as ex:
        bad += 1; continue
    ev = {'rule': f, 'id': d.get('id'), 'fields': [], 'sys': {}}
    for c in e:
        tag = strip(c.tag)
        if tag == 'System':
            for s in c:
                st = strip(s.tag)
                if st == 'Provider': ev['sys']['provider'] = s.get('Name', '')
                elif st == 'EventID': ev['sys']['eid'] = int((s.text or '0').strip())
                elif st == 'Channel': ev['sys']['channel'] = (s.text or '').strip()
                elif st == 'Computer': ev['sys']['computer'] = (s.text or '').strip()
                elif st == 'Level': ev['sys']['level'] = int((s.text or '0').strip() or 0)
                elif st == 'Security': ev['sys']['user'] = s.get('UserID', '')
        elif tag == 'EventData':
            k = 0
            datas = [s for s in c]
            unnamed = [s for s in datas if strip(s.tag) == 'Data' and s.get('Name') is None]
            for s in datas:
                name = s.get('Name') or strip(s.tag)
                if s.get('Name') is None and strip(s.tag) == 'Data' and len(unnamed) > 1:
                    k += 1; name = f'Data[{k}]'
                ev['fields'].append([name, s.text or ''])
        elif tag == 'UserData':
            def walk(el):
                kids = list(el)
                if not kids:
                    ev['fields'].append([strip(el.tag), el.text or '']); return
                for kk in kids: walk(kk)
            for w in c:
                for kk in w: walk(kk)
    out.write(json.dumps(ev) + '\n'); n += 1
print(n, 'samples', bad, 'unparsable', file=sys.stderr)
