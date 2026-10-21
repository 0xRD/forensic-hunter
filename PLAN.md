# Plan

Forensic Hunter (`forhunt`): a single static Rust binary for very fast Windows
artifact analysis (EVTX in v1), plus a Claude skill that runs a systematic,
checklist-driven DFIR method on top of it. The full specification lives in the
project brief; this file tracks how it is executed. Progress is in STATUS.md,
decisions in DECISIONS.md, blockers in BLOCKERS.md.

## Architecture

```
crates/forhunt-core     event model (EventView), Artifact/Source traits, EVTX source,
                        JSON scanner, filters, field maps (maps/default.toml),
                        input expansion, order-preserving parallel engine
crates/forhunt-output   writers: csv, jsonl (full fidelity), llm (compact)
crates/forhunt          CLI binary `forhunt`: parse, stats, search, timeline, show, hayabusa
tools/evtx-gen          synthetic EVTX generator (fixtures, multi-GB bench corpus)
skill/                  Claude skill: SKILL.md, install scripts, references, checklists
```

Hot path: mmap file -> 64 KiB chunk = unit of work -> `evtx` chunk parse and
JSON render -> custom JSON scanner into a borrowed `EventView` -> filter ->
writer appends to a per-unit buffer -> consumer writes units in order.

## Phases

0. Plan, decisions, workspace scaffold, CI. *(main agent)*
1. Research subagents write `skill/references/checklists/*.yaml` per tactic group
   while the main agent builds the core. *(5 Sonnet subagents)*
2. `parse` + baseline bench, `stats`, `search`, `llm` format, `timeline`, `show`,
   `hayabusa`; integration tests on valid/corrupt/truncated inputs. *(main agent)*
3. Verifier (flips `verified`), performance analyst, fresh-eyes reviewer
   *(Sonnet subagents)*; skill workflow, install scripts, report template,
   worked example; release workflow and Homebrew tap job.

## Definition of done

See the brief; tracked item by item in STATUS.md.
