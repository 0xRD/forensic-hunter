# Incident report template

Fill every section. Write "None observed" only when the relevant log source
was present; otherwise state the gap. Times in UTC (ISO 8601). Every fact
carries an event reference id (`<file key>:<record id>`) that `forhunt show`
resolves.

---

# <Case name>: Windows event log analysis

| | |
|---|---|
| Analyst | Claude (Forensic Hunter skill), for <requester> |
| Date of report | <YYYY-MM-DD> |
| Scope | <hosts, log files, time range analysed> |
| Tools | forhunt <version>, Hayabusa <version> (rules <date>) |

## 1. Executive summary

3-6 sentences for a non-technical reader: what happened, when, which
systems and accounts, impact, whether the activity appears contained, overall
confidence, the most important action to take.

## 2. Evidence and integrity

| File | Host | SHA-256 (before) | SHA-256 (after) | Events | First event | Last event | Notes |
|---|---|---|---|---|---|---|---|

Acquisition: <who, when, how>. Integrity: hashes before and after analysis
<match / do not match>. Corruption: <bad chunks/records from forhunt, or none>.

## 3. Key findings

Numbered, most important first. For each:

**F1. <Title>** - *Confidence: High/Medium/Low*
- Observed: <facts with event ids>
- Inferred: <interpretation, clearly labelled>
- ATT&CK: <Txxxx.yyy name>
- Checklist: <FH-XXX-NNN ids>

## 4. Timeline

Full chronological table of relevant events (not only detections).

| # | Time (UTC) | Host | Account | Event ref | Description | ATT&CK | Confidence |
|---|---|---|---|---|---|---|---|
| 1 | 2024-03-11T10:00:00Z | WS-07 | - | 4a2aa2ed:53276 | First of 37 failed logons (4625) from 203.0.113.50 | T1110.003 | High |

Use `Observed` descriptions; mark inferred rows with "(inferred)".

## 5. Attack narrative

The story in prose, phase by phase (initial access, execution, persistence,
privilege escalation, defense evasion, credential access, discovery, lateral
movement, collection/exfiltration, impact), each step pointing to timeline
rows. Explicitly mark gaps in the chain and alternative explanations.

## 6. Indicators of compromise

| Type | Value | First seen (UTC) | Last seen (UTC) | Context | Event refs |
|---|---|---|---|---|---|
| IP | | | | | |
| Account | | | | | |
| Host | | | | | |
| File/path | | | | | |
| Hash | | | | | |
| Service/task | | | | | |
| Command line | | | | | |

## 7. Checklist coverage

| Tactic | Checks | HIT | NO_HIT | NOT_APPLICABLE | LOG_SOURCE_MISSING |
|---|---|---|---|---|---|

Full per-check status: `checklist-status.md` (attach or append).

## 8. Gaps and blind spots

- Log sources absent or disabled (e.g. no Sysmon, no 4688 command line, no
  PowerShell script block logging, no DC logs) and what this hides
  (see `checklists/INDEX.md`, blind spots).
- Time periods without logs (quiet periods, record-id gaps, log clearing).
- Hosts in scope without logs.
- Limits of the analysis (rules not verified, heuristics).

## 9. Recommendations

Immediate containment, eradication, recovery, then logging and detection
improvements tied to the gaps above. Each recommendation references the
finding or gap it addresses.

## Appendix

- Attack path diagram (optional): Mermaid source and/or HTML file.
- Commands run (key `forhunt`/`hayabusa` invocations).
