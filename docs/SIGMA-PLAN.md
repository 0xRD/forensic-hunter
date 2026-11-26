# Sigma detection in forhunt and forhunt-viewer: plan

Status: done (2026-11-26), forhunt 0.8.0 and forhunt-viewer 0.9.0, both
unreleased. Replaces the external Hayabusa binary with a built-in Sigma engine
shared by `forhunt` and `forhunt-viewer`. Outcome and measurements: section 7.

## 1. Can we use the Hayabusa rules?

Yes, with attribution. The rules in
[Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)
(Hayabusa's own rules and its curated copy of SigmaHQ's) are released under the
[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License):
use, copy, modify and redistribute freely, on two conditions.

| Condition (DRL 1.1) | How we meet it |
|---|---|
| Sharing the rules: keep the author, a link to the rule set and the licence | We do not share them: the rules are never bundled, they are downloaded by the user (viewer *Settings*, skill installer) straight from the Yamato Security repository. The download screen names the rule set, its licence and links to both. |
| Using the rules on data: messages based on matches keep the rule's `author` | Every detection carries the rule's author: `forhunt sigma` output (`auth` key), the viewer's detection panel and detail pane. |

What we must not do: link or copy code from Hayabusa itself (GPL-3.0; our
crates are MIT/Apache-2.0). The engine is written from the public Sigma
specification and the rule files, clean-room, like the rest of the project.

## 2. Where the code goes

```
forensic-hunter/crates/forhunt-core/src/sigma/   the engine (shared)
    load.rs      YAML -> rules; Hayabusa config (exclusions, noisy, level tuning, aliases)
    compile.rs   detection -> matcher tree; condition parser
    eval.rs      matching an EventView; candidate index by (Channel, EventID)
forensic-hunter/crates/forhunt/src/cmd/sigma.rs  `forhunt sigma`
forhunt-viewer/crates/fhv-app/src/sigma*.rs      rules settings, download, run job, UI
```

The engine evaluates `forhunt_core::EventView`. forhunt feeds it events
straight from the evidence; the viewer builds an `EventView` from a CSV row
(system columns + the `Payload` JSON of forhunt and EvtxECmd CSVs, or the
columns themselves for any other CSV), so one engine serves both.

## 3. Engine design (speed first)

1. **Load once**: parse every `.yml` (yaml-rust2, pure Rust, MIT/Apache),
   compile values into matchers up front: lowercase needles with prebuilt
   `memchr::memmem` finders, wildcard patterns split into pieces, regexes
   compiled once, CIDR parsed, base64 / windash / UTF-16 variants expanded.
2. **Candidate index**: from each rule's condition, derive the set of
   `Channel` and `EventID` values it can match (abstract evaluation of the
   AND/OR/NOT tree). Per event only the rules of its (channel, event id) are
   tried; the lookup is cached per thread. Nearly every Hayabusa rule names
   both, so an event is tested against a handful of rules, not 4,000.
3. **Skip decoding**: forhunt's parser asks `want_event_id` before decoding a
   record; event ids no rule can match are never decoded.
4. **Lazy lowercase**: an event's field values are lowercased at most once,
   on first use, shared by all its rules.
5. **Viewer**: the `Channel` / `EventId` columns are dictionary-indexed, so the
   candidate rows are a bitmap union computed without reading the file; only
   blocks holding candidate rows are read, in parallel, cancellable.

Supported: every field modifier used by the rule set (`contains`, `startswith`,
`endswith`, `all`, `re` with `i`/`m`/`s`, `windash`, `cidr`, `base64`,
`base64offset`, `wide`/`utf16le`/`utf16be`/`utf16`, `fieldref`,
`equalsfield`, `endswithfield`, `exists`, `gt`/`gte`/`lt`/`lte`, `cased`,
`expand`), wildcards `*` `?` with `\` escapes, `null`, keyword lists,
conditions with `and`/`or`/`not`/parentheses/`1 of`/`all of`/`them`.
Hayabusa defaults: `deprecated`/`unsupported` rules and `exclude_rules.txt`
skipped, `noisy_rules.txt` skipped unless asked, `level_tuning.txt` applied,
`eventkey_alias.txt` field aliases. Phase 2: correlation rules
(`event_count`, `value_count`, `temporal`) and the deprecated `| count()`.

## 4. forhunt CLI

`forhunt sigma <evidence...> [-R rules-dir]... [--min-level medium] [-g]
[--noisy] [--rule-id id]`: one parallel pass, detections in the same compact
`llm` form as `forhunt hayabusa` (forhunt ids, rule, level, MITRE tags,
author, details), `-g` grouping, summary with top rules and hosts; `-F jsonl`
and `-F csv` for full output. Rules default to the folder the skill installer
fills. Works on every forhunt artifact: custom rules can target `Prefetch`,
`Registry`, `MFT`, `UsnJrnl`, `Mail` channels with forhunt's field names.

Skill: the installer downloads the rules (pinned commit, SHA-256 checked)
instead of the Hayabusa binary; SKILL.md uses `forhunt sigma`;
`forhunt hayabusa` stays for existing Hayabusa output. A new reference,
`skill/references/sigma-rules.md`, teaches Claude to write and test rules for
forhunt (field names per artifact, supported modifiers, test loop).

## 5. Viewer UX

- **Settings > Detection rules**: *Download Hayabusa rules* / *Update* (shows
  rule count, date, source, DRL 1.1 notice with links), *Add rules folder…*
  for your own rules (each with its rule count and load errors), minimum
  level, include noisy rules. Nothing is downloaded without a click.
- **Run**: a *Detect* button in the toolbar (also *Tools > Run Sigma
  detection*, Ctrl+Shift+D). Explicit, never automatic: matching can take
  seconds on huge files and the analyst decides when. Disabled with a tooltip
  saying why (no rules yet: "Download rules in Settings"). Progress and Esc
  cancel like every other job. After a run the button shows the detection
  count; changing rules marks results stale ("Re-run").
- **Results** (recommendation: color for context, filter for focus):
  - a **Detections panel** (side panel): rules grouped by level, with counts;
    click a rule to filter to its rows (a chip `Sigma: <title>`, removable like
    any chip), a level header to filter to that level, *Only detections* to
    keep every matched row;
  - matched rows get a **level marker** in the row gutter and a light tint of
    the level color (critical, high, medium, low, informational), so
    detections stay visible in the full timeline, between the events around
    them. User coloring rules win over the tint;
  - the **detail pane** lists the row's rules (title, level, author, MITRE
    tags, description, references) and highlights the fields those rules
    test; in CSVs whose columns are event fields, those cells are
    highlighted in the grid too.

## 6. Verification

- Unit tests per modifier and condition form, against hand-written events.
- Every rule of the Hayabusa set loads, or is reported with a reason
  (counted, never silent).
- Sigma's own regression samples where reachable; forhunt synthetic fixtures
  with known attacks (encoded PowerShell, log cleared, failed logons).
- The same rules on the same evidence give the same detections in `forhunt
  sigma` and in the viewer (one engine, two event sources).
- Throughput measured with `scripts/bench.sh`-style runs and recorded in PERF.md.

## 7. Outcome

- Engine: 4,686 of the 5,020 rule files load (the rest skipped by design and
  counted: deprecated, unsupported, excluded, noisy, correlation, `expand`
  without values; 1 file has no condition). 98 of 99 loadable rules match the
  sample event they embed (the 99th sample is empty in its rule file).
- Speed: Hayabusa's 599 sample logs (47,685 events) against 4,686 rules,
  `forhunt sigma`: 0.83 s on 4 cores including 0.2 s of rule loading; one
  thread, matching only: 19 s naive -> 0.53 s (literal gates, D-064). Gated
  and ungated matching agree on every event.
- Viewer: same 17,920 (event, rule) pairs as the CLI on the same logs;
  1.65 M rows (1 GB) in 4.9 s on 4 cores.
- Changed from the plan: the toolbar button is *Detect* (no symbol: the bundled
  fonts lack it); without rules it opens Settings at the rules section; the
  Detections panel is on the left (the detail pane is on the right); the
  viewer downloads the newest rules (HTTPS), the skill installer a pinned
  commit with a content digest.
- Not done yet: correlation rules and `| count()`; Sigma `logsource` mapping
  for upstream SigmaHQ rules that name neither channel nor event id;
  detections in viewer sessions. The skill installer's PowerShell path is
  written but untested here (no PowerShell in this environment), and the
  viewer's real download from GitHub could not be exercised from this sandbox
  (its proxy refuses GitHub archives); the unpack/install path is tested.
