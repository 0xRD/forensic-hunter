#!/usr/bin/env python3
"""Validates skill/references/checklists/*.yaml against SCHEMA.md and generates
INDEX.md (tactic order, coverage matrix, blind spots) and
checklist-status-template.md.

usage: scripts/gen-checklist-index.py [--check]
  --check  fail if the generated files are out of date (CI)
"""
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CL = ROOT / "skill/references/checklists"
INDEX = CL / "INDEX.md"
TEMPLATE = ROOT / "skill/references/checklist-status-template.md"
JSON = CL / "checklists.json"

# Walk order: roughly the attack lifecycle, AD and remote access after the
# tactics they feed.
ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "remote-access", "active-directory", "collection-exfiltration", "impact",
    "filesystem",
]
PREFIX = {
    "initial-access": "INIT", "execution": "EXE", "persistence": "PER",
    "privilege-escalation": "PRV", "defense-evasion": "DEF",
    "credential-access": "CRED", "discovery": "DISC", "lateral-movement": "LAT",
    "remote-access": "RMT", "active-directory": "AD",
    "collection-exfiltration": "COLL", "impact": "IMP", "filesystem": "FS",
}
REQUIRED = ["id", "title", "tactic", "attack", "channel", "event_ids", "prerequisites",
            "logic", "pivots", "false_positives", "severity", "sources", "verified"]
SEVERITIES = {"informational", "low", "medium", "high", "critical"}

# Coverage matrix columns: log source -> predicate on the channel string.
SOURCES = [
    ("Security", lambda c: c.lower() == "security"),
    ("System", lambda c: c.lower() == "system"),
    ("Sysmon", lambda c: "sysmon" in c.lower()),
    ("PowerShell", lambda c: "powershell" in c.lower()),
    ("WMI", lambda c: "wmi" in c.lower()),
    ("TaskSched", lambda c: "taskscheduler" in c.lower()),
    ("RDP/TS", lambda c: "terminalservices" in c.lower() or "rdp" in c.lower()),
    ("WinRM", lambda c: "winrm" in c.lower()),
    ("Defender", lambda c: "defender" in c.lower()),
    ("NTFS", lambda c: c in ("MFT", "UsnJrnl")),
    ("Other", None),
]

BLIND_SPOTS = """\
What stays invisible when a log source or audit setting is missing. When a
check's source is absent, its status is `LOG_SOURCE_MISSING`, never `NO_HIT`,
and the gap goes into the report.

| Missing source / setting | What you cannot see | Checks affected |
|---|---|---|
| Security log: *Audit Logon* (4624/4625/4634/4648/4672) | who logged on, from where, with which logon type; brute force and spraying; pass-the-hash patterns; RDP/SMB/WinRM logons | initial-access, lateral-movement, remote-access, privilege-escalation |
| Security log: *Audit Process Creation* (4688) and the *Include command line* GPO | process executions and their command lines (without the GPO, 4688 has no `CommandLine`) | execution, discovery, defense-evasion, impact (unless Sysmon 1 is present) |
| Security log: *Audit Security System Extension* (4697) / *Other Object Access* (4698-4702) | service and scheduled-task creation in Security (System 7045 and TaskScheduler/Operational still help) | persistence, lateral-movement |
| Security log: *Account Management* (4720-4738, 4741-4767) | account creation, group membership changes, password resets | persistence, privilege-escalation, active-directory |
| Domain controller Security logs (Kerberos 4768/4769/4771, NTLM 4776, DS Access 4662, DS Changes 5136) | Kerberoasting, AS-REP roasting, DCSync, golden/silver ticket anomalies, GPO/AdminSDHolder/delegation changes; workstation logs alone cannot show them | active-directory, credential-access |
| *Detailed File Share* (5145) / *File Share* (5140) | admin share use, PsExec/impacket named pipes, SYSVOL writes, coercion pipes | lateral-movement, active-directory, collection-exfiltration |
| Sysmon (not installed, or config not logging the event) | process tree with hashes and parent command line (1), network connections (3), image loads (7), remote threads (8), LSASS access (10), file creation (11), registry (12-14), WMI subscriptions (19-21), DNS (22), file deletion (23/26) | most execution, credential-access (LSASS), collection-exfiltration (DNS), defense-evasion checks |
| PowerShell Script Block Logging (4104) and Module Logging (4103) | script contents, decoded `-EncodedCommand`, download cradles, AMSI bypass strings | execution, defense-evasion |
| PowerShell v2 engine events (Windows PowerShell 400/600) | downgrade attacks (v2 bypasses script block logging) | defense-evasion |
| TaskScheduler/Operational | task registration/run details beyond 4698 | persistence |
| TerminalServices-* / RdpCoreTS | RDP session lifecycle and source address (1149, 21-25, 131) | remote-access, lateral-movement |
| WinRM/Operational | PowerShell remoting sessions | remote-access, lateral-movement |
| Windows Defender/Operational | detections (1116/1117) and tampering (5001/5007/5010/5012/5013) | defense-evasion, credential-access |
| Certificate Services auditing on the CA (4886-4900) | ADCS abuse (ESC1-ESC8) | active-directory |
| `$MFT` / `$UsnJrnl:$J` not collected (or journal wrapped) | file creation, renames, deletions, timestomping, downloaded files (Zone.Identifier) when event logs are absent or cleared; the journal only covers its retention window | filesystem |
| Retention: log rolled over or cleared | anything before the first event; check `stats` first/last time, `log_tampering`, `rid_gaps`, `quiet_periods` | all |
| Not in EVTX at all | VPN/firewall/proxy logs, EDR telemetry, file contents, memory, network bytes transferred, browser history | exfiltration volume, C2 content, initial access via external services |
"""


def load():
    files = {}
    problems = []
    seen = {}
    for p in sorted(CL.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text())
        tactic = p.stem
        if tactic not in PREFIX:
            problems.append(f"{p.name}: unknown tactic file")
            continue
        checks = doc.get("checks") or []
        for c in checks:
            cid = c.get("id", "?")
            for k in REQUIRED:
                if k not in c:
                    problems.append(f"{p.name} {cid}: missing `{k}`")
            if not re.fullmatch(rf"FH-{PREFIX[tactic]}-\d{{3}}", str(cid)):
                problems.append(f"{p.name} {cid}: id should be FH-{PREFIX[tactic]}-NNN")
            if cid in seen:
                problems.append(f"{p.name} {cid}: duplicate id (also in {seen[cid]})")
            seen[cid] = p.name
            if c.get("severity") not in SEVERITIES:
                problems.append(f"{p.name} {cid}: bad severity {c.get('severity')!r}")
            if not isinstance(c.get("verified"), bool):
                problems.append(f"{p.name} {cid}: `verified` must be true/false")
            if not c.get("sources"):
                problems.append(f"{p.name} {cid}: no sources")
            if not isinstance(c.get("event_ids"), list):
                problems.append(f"{p.name} {cid}: event_ids must be a list")
        files[tactic] = (doc, checks)
    for t in ORDER:
        if t not in files:
            problems.append(f"missing checklist for tactic {t}")
    return files, problems


def channel_of(c):
    ch = c.get("channel", "")
    return ", ".join(ch) if isinstance(ch, list) else str(ch)


def source_col(ch):
    for name, pred in SOURCES:
        if pred and any(pred(x.strip()) for x in ch.split(",")):
            return name
    return "Other"


def gen(files):
    total = sum(len(v[1]) for v in files.values())
    ver = sum(1 for v in files.values() for c in v[1] if c.get("verified") is True)
    out = ["# Checklist index", "",
           "Generated by `scripts/gen-checklist-index.py` from the YAML files; do not edit by hand.", "",
           f"{total} checks in {len(files)} tactics, {ver} verified by two independent sources "
           f"(see `VERIFICATION.md` when present, and `verified`/`notes` per check).", "",
           "## Walk order", ""]
    for i, t in enumerate(ORDER, 1):
        if t in files:
            doc, checks = files[t]
            n_ver = sum(1 for c in checks if c.get("verified") is True)
            out.append(f"{i}. [{doc.get('title', t)}]({t}.yaml): {len(checks)} checks ({n_ver} verified)")
    out += ["", "## Coverage matrix", "",
            "Checks per tactic and primary log source (a check counts once, under the first source of its channel).", ""]
    cols = [s[0] for s in SOURCES]
    out.append("| Tactic | " + " | ".join(cols) + " | Total |")
    out.append("|---" * (len(cols) + 2) + "|")
    sums = Counter()
    for t in ORDER:
        if t not in files:
            continue
        cnt = Counter(source_col(channel_of(c)) for c in files[t][1])
        sums.update(cnt)
        out.append(f"| {t} | " + " | ".join(str(cnt.get(k, "")) for k in cols) + f" | {sum(cnt.values())} |")
    out.append("| **total** | " + " | ".join(str(sums.get(k, "")) for k in cols) + f" | {sum(sums.values())} |")
    out += ["", "## Blind spots", "", BLIND_SPOTS, "## All checks", ""]
    for t in ORDER:
        if t not in files:
            continue
        doc, checks = files[t]
        out += [f"### {doc.get('title', t)}", "",
                "| Id | Title | Channel | Event ids | Severity | Verified |", "|---|---|---|---|---|---|"]
        for c in checks:
            ids = ", ".join(str(x) for x in (c.get("event_ids") or []))
            title = str(c.get("title", "")).replace("|", "/")
            out.append(f"| {c['id']} | {title} | {channel_of(c)} | {ids} | {c.get('severity')} | "
                       f"{'yes' if c.get('verified') else 'no'} |")
        out.append("")
    index = "\n".join(out).rstrip() + "\n"

    t = ["# Checklist status", "",
         "Copy to the case working directory. Every row must end with one status:",
         "`HIT`, `NO_HIT`, `NOT_APPLICABLE` or `LOG_SOURCE_MISSING`. Evidence: event ids",
         "for HIT; the query and scope for NO_HIT; the missing source or reason otherwise.", "",
         "Case: <name>  Evidence: <path>  Analyst: <name>  Started: <UTC time>", ""]
    for tac in ORDER:
        if tac not in files:
            continue
        doc, checks = files[tac]
        t += [f"## {doc.get('title', tac)}", "", "| Id | Check | Source | Status | Evidence / reason |", "|---|---|---|---|---|"]
        for c in checks:
            title = str(c.get("title", "")).replace("|", "/")
            t.append(f"| {c['id']} | {title} | {channel_of(c)} {','.join(str(x) for x in (c.get('event_ids') or []))} |  |  |")
        t.append("")
    t += ["## Summary", "", "| Tactic | HIT | NO_HIT | NOT_APPLICABLE | LOG_SOURCE_MISSING |", "|---|---|---|---|---|"]
    t += [f"| {tac} |  |  |  |  |" for tac in ORDER if tac in files]
    import json
    machine = {"version": 1, "checks": []}
    for tac in ORDER:
        if tac not in files:
            continue
        for c in files[tac][1]:
            ch = c.get("channel", "")
            chans = ch if isinstance(ch, list) else [x.strip() for x in str(ch).split(",") if x.strip()]
            fq = c.get("forhunt") or []
            machine["checks"].append({
                "id": c["id"], "title": str(c.get("title", "")), "tactic": tac,
                "channels": chans, "event_ids": [int(x) for x in (c.get("event_ids") or []) if str(x).isdigit()],
                "forhunt": [q for q in fq if isinstance(q, str)],
                "severity": c.get("severity"), "verified": bool(c.get("verified")),
            })
    machine_json = json.dumps(machine, indent=1, ensure_ascii=False) + "\n"
    return index, "\n".join(t).rstrip() + "\n", machine_json


def main():
    check = "--check" in sys.argv
    files, problems = load()
    for p in problems:
        print("checklist:", p, file=sys.stderr)
    index, template, machine = gen(files)
    if check:
        stale = [p for p, s in ((INDEX, index), (TEMPLATE, template), (JSON, machine)) if not p.exists() or p.read_text() != s]
        for p in stale:
            print(f"out of date: {p.relative_to(ROOT)} (run scripts/gen-checklist-index.py)", file=sys.stderr)
        sys.exit(1 if problems or stale else 0)
    INDEX.write_text(index)
    TEMPLATE.write_text(template)
    JSON.write_text(machine)
    print(f"wrote {INDEX.relative_to(ROOT)} and {TEMPLATE.relative_to(ROOT)}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
