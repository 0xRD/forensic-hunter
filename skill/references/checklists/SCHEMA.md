# Checklist schema

Each file under `references/checklists/` covers one tactic and is a YAML document:

```yaml
tactic: credential-access          # file slug
title: Credential Access
description: >
  One paragraph: what this tactic looks like in Windows event logs.
checks:
  - id: FH-CRED-001                # FH-<PREFIX>-NNN, unique, never reused
    title: Kerberoasting - RC4 service ticket requests
    tactic: credential-access
    attack: [T1558.003]            # MITRE ATT&CK technique ids
    channel: Security              # channel name as written in the EVTX <Channel> element
    provider: Microsoft-Windows-Security-Auditing   # optional
    event_ids: [4769]
    prerequisites:                 # what must be enabled for the events to exist
      - "Audit Kerberos Service Ticket Operations (Success) on domain controllers"
    logic:                         # sigma-like; field names = EVTX EventData/System names
      selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
      filter_machine_accounts:
        ServiceName|endswith: '$'
      condition: selection and not filter_machine_accounts
    forhunt:                       # one or more ready-to-run narrowing queries
      - forhunt search <paths> --channel Security --event-id 4769 --field TicketEncryptionType=0x17 --format llm
    pivots:                        # what to look at next when this hits
      - "Requesting account (TargetUserName) -> 4624 logons from IpAddress"
    false_positives:
      - "Legacy applications that only support RC4"
    severity: high                 # informational | low | medium | high | critical
    sources:                       # URLs actually read
      - https://learn.microsoft.com/...
      - https://attack.mitre.org/techniques/T1558/003/
    verified: false                # true ONLY if confirmed by >= 2 independent sources
    notes: "optional free text: version caveats, thresholds, Sysmon config dependencies"
```

## Rules

- **Field names** are the names that appear in the rendered event: `System` fields
  (`EventID`, `Channel`, `Computer`, `Provider`, `TimeCreated`) and `EventData`/`UserData`
  field names exactly as Windows writes them (`TargetUserName`, `LogonType`, `IpAddress`,
  `NewProcessName`, `CommandLine`, `ServiceFileName`, `ImagePath`, ...).
- **Sigma modifiers** allowed: `|contains`, `|startswith`, `|endswith`, `|re`, `|all`, `|gte`, `|lte`.
  Aggregations (counts over time windows) go in `condition` as plain text,
  e.g. `count(selection) by IpAddress > 20 within 5m`.
- **forhunt CLI** available for `forhunt:` entries:
  `forhunt search <paths> [--event-id N[,N...]] [--channel NAME] [--since TS] [--until TS]
  [--field Name=value]... [--field Name~substring]... [--regex Name=REGEX] [--computer HOST]
  [--limit N] [--format llm|jsonl|csv]`, `forhunt stats <paths> --format llm`,
  `forhunt timeline <paths> --since TS --until TS --format llm`.
  `--field Name=value` is a case-insensitive exact match, `Name~value` a case-insensitive substring.
- **Licensing**: write everything in your own words. Never paste rule bodies from SigmaHQ,
  Hayabusa, Chainsaw or any other project (DRL / GPL). Cite them by URL.
- **verified**: `true` only when two *independent* sources (e.g. Microsoft docs + a JPCERT
  report, not two blogs quoting each other) confirm the event id, the channel and the field
  semantics used in `logic`. Otherwise `false`, with a `notes` line saying what is unconfirmed.
- Every check must name its `prerequisites` honestly: Sysmon-based checks say
  "Sysmon installed with a config that logs event N"; 4688 command lines need
  "Include command line in process creation events" GPO; 4104 needs Script Block Logging.
- Prefer fewer, precise checks over many vague ones. Aim for roughly 8-20 checks per tactic.
