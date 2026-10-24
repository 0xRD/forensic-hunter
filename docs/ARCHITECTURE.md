# Architecture

```
crates/forhunt-core     event model (EventView), Artifact/Source traits, EVTX and
                        NTFS ($MFT, $UsnJrnl:$J) sources, JSON scanner, filters,
                        field maps (maps/default.toml), input expansion and
                        opening (input::open_all), order-preserving parallel engine
crates/forhunt-output   writers: csv (EvtxECmd layout + ForhuntId), jsonl (full
                        fidelity), llm (compact); export::write_all for library users
crates/forhunt          CLI binary `forhunt`: parse, stats, search, timeline, show,
                        hayabusa, checklist
tools/evtx-gen          synthetic EVTX / NTFS generator (fixtures, multi-GB corpus)
skill/                  Claude skill: SKILL.md, install scripts, references,
                        detection checklists (YAML + generated JSON index)
```

Hot path: positional read (D-021) -> 64 KiB chunk = unit of work -> `evtx`
chunk parse (fast template decoder, JSON fallback) -> scanner into a borrowed
`EventView` -> filter -> writer appends to a per-unit buffer -> the consumer
writes units in input order, so output is deterministic whatever the thread
count.

A new artifact type implements `Artifact` (recognise a file by its first bytes
or name, open it) and `Source` (split into independent units, parse a unit
into events); the engine, filters, writers and every command then work on it
unchanged.

Library use (forhunt-viewer): `forhunt_core::input::open_all` expands paths,
opens inputs in parallel, skips duplicates and returns warnings;
`forhunt_output::export::write_all` streams every event through a writer with
progress and cancellation. The CSV it writes is byte-identical to
`forhunt parse -F csv`. Pin a release tag as a git dependency (D-044).
