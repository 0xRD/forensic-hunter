# Worked examples

Real sessions with the commands run and their (abridged) outputs.

| Example | Data | Shows |
|---|---|---|
| [insecurebank-case.md](insecurebank-case.md) | EVTX-ATTACK-SAMPLES, `insecurebank.local` domain files (public, GPL-3.0, fetched by `scripts/fetch-samples.sh`) | full workflow: intake, stats, Hayabusa, checklist walk, pivots, timeline, final report with Mermaid attack path |
| [synthetic-ws07.md](synthetic-ws07.md) | `fixtures/synthetic` (generated, in this repository) | short end-to-end run on the built-in attack scenario; reproducible offline |

Outputs are trimmed with `…` where long; event ids are real and resolve with
`forhunt show <id> -p <evidence>` on the same files.
