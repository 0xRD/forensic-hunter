# Hayabusa

[Hayabusa](https://github.com/Yamato-Security/hayabusa) is a fast Windows
event log forensics timeline generator and threat hunting tool by Yamato
Security, using Sigma and Hayabusa rules.

**Licence notice.** Hayabusa is licensed under the GNU General Public License
v3.0; its rules are under the Detection Rule License (DRL) 1.1. Forensic
Hunter does not include, link or modify Hayabusa: `scripts/install.sh` and
`scripts/install.ps1` download the official release archives from
https://github.com/Yamato-Security/hayabusa/releases and verify their
SHA-256 against `scripts/hayabusa.sha256`. Source code:
https://github.com/Yamato-Security/hayabusa.

## Commands (4.x)

Hayabusa 4.x merged `csv-timeline` and `json-timeline` into `dfir-timeline`
with `-t/--output-type csv|json|jsonl`. With 3.x, use `csv-timeline` or
`json-timeline` (`-L` for JSONL) with the same options.

| Task | Command |
|---|---|
| Detections timeline for forhunt | `hayabusa dfir-timeline -d DIR -t jsonl -p verbose -O -w -q -K -N -C -o out.jsonl` |
| CSV timeline for a human | `hayabusa dfir-timeline -d DIR -t csv -p standard -O -w -o out.csv` |
| Logon summary | `hayabusa logon-summary -d DIR -o logons` (prefix: writes two CSV files) |
| Event id metrics | `hayabusa eid-metrics -d DIR` |
| Computers | `hayabusa computer-metrics -d DIR` |
| Keyword/regex search | `hayabusa search -d DIR -k "mimikatz" -o hits.csv` / `-r "regex"` |
| Base64 extraction | `hayabusa extract-base64 -d DIR` |
| Update rules | `hayabusa update-rules` |
| One file | `-f FILE` instead of `-d DIR` |

Useful options: `-w` no wizard (all rules), `-m/--min-level <level>`,
`-e/--exact-level`, `--timeline-start "2024-03-11 10:00:00 +00:00"`,
`--timeline-end`, `--include-eid`/`--exclude-eid`, `--include-computer`,
`-E` common EIDs only (faster), `-n` enable noisy rules, `-D` deprecated,
`-u` unsupported, `-x` carve records from slack space, `-U` UTC, `-O` ISO 8601
UTC timestamps, `-K` no colour, `-N` no summary, `-q` quiet, `-C` overwrite.

Profiles (`-p`): `minimal`, `standard`, `verbose` (adds MITRE tactics/tags,
rule file and **EvtxFile**), `all-field-info`, `super-verbose`,
`timesketch-*`. Use `verbose` so `forhunt hayabusa` can map detections to
forhunt ids.

## Levels

`informational` < `low` < `medium` < `high` < `critical` (output may
abbreviate: `info`, `med`, `crit`; `emergency` exists in some rule sets).
Start with `--min-level medium`, then look at `low` for the time windows
that matter.

## Normalising for the analysis

```bash
forhunt hayabusa out.jsonl -p "$CASE/evidence" --min-level medium -n 200
```
Output lines: `id` (forhunt id or null), `t`, `h`, `ch`, `eid`, `rec`
(Hayabusa RecordID), `lvl`, `rule`, `mitre`, `d` (details). The summary has
counts per level, top rules and hosts. With a cap, the most severe detections
are kept. Each detection is a lead: confirm with `forhunt show <id>` and the
surrounding timeline before reporting it as a finding.
