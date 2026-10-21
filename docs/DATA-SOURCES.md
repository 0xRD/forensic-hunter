# Data sources and licences

Nothing below is committed to this repository unless marked *committed*.

| Data | Licence | Use | How it is obtained |
|---|---|---|---|
| `fixtures/synthetic/*.evtx` (*committed*) | MIT OR Apache-2.0 (generated) | tests, examples in docs | `cargo run -p evtx-gen -- fixtures`; synthetic hosts (`contoso.local`), documentation IP ranges (RFC 5737); CI checks they are reproducible byte for byte |
| Benchmark corpus | MIT OR Apache-2.0 (generated) | benchmarks, CI perf gate | `evtx-gen corpus --size 2G` (`scripts/bench.sh`, `scripts/bench-gate.sh`) |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | GPL-3.0 | worked examples, checklist verification against real field names | `skill/scripts/fetch-samples.sh` (git clone, pinned commit); outputs quoted in examples are short excerpts |
| [evtx crate samples](https://github.com/omerbenamram/evtx/tree/master/samples) | repository MIT/Apache-2.0 | manual robustness testing (dirty, corrupt files) | git clone; not used by CI |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) binary | GPL-3.0 | detections in the skill workflow | `skill/scripts/install.sh`/`install.ps1`, SHA-256 pinned in `skill/scripts/hayabusa.sha256` |
| Hayabusa / Sigma rules | DRL 1.1 | shipped inside the Hayabusa archive; cited (never copied) by the checklists | as above |
| Checklist content (`skill/references/`) | MIT OR Apache-2.0 | skill | written for this project; sources cited by URL |

Rust dependencies are checked by `cargo deny` (`deny.toml`): permissive
licences only, no copyleft in the binary.
