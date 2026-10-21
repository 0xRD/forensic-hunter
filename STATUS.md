# Status

Last update: 2026-10-21

## Done
- Spec review, PLAN.md, DECISIONS.md, BLOCKERS.md
- Workspace: forhunt-core (event model, Artifact/Source traits, EVTX source with
  mmap, panic isolation, truncated-tail recovery; JSON scanner; filters; field
  maps; input expansion; parallel ordered engine), forhunt-output (csv, jsonl, llm)
- CLI: `parse`, `search` (with llm summary + narrowing suggestions)
- Research phase: 12 checklist files (~260 checks) + sources, eventids.md, logontypes.md

## In progress
- `stats`, `timeline`, `show`, `hayabusa`

## Next
- evtx-gen + fixtures (valid, corrupt, truncated), integration tests
- CI, cargo deny, benches + regression gate
- Skill: SKILL.md, install scripts, INDEX.md, report template, worked example
- Phase 3 subagents: verifier, perf analyst, reviewer
- Release workflow (cargo-dist), tap job (deferred, B-002)
