# Blockers

Items that need a human or a different environment. Work continues around them.

| # | Blocker | Impact | What is needed |
|---|---------|--------|----------------|
| B-001 | The build container's network allows only GitHub (git and raw.githubusercontent.com). learn.microsoft.com, attack.mitre.org, JPCERT/CC, SANS, The DFIR Report, NSA, ANSSI, crates.io API and formulae.brew.sh are unreachable. | Checklist `verified` flags rest on GitHub-hosted sources (SigmaHQ, Hayabusa, Chainsaw, Microsoft Sysmon docs source, MITRE CTI data, JPCERT ToolAnalysisResultSheet repo). No check is confirmed against a Microsoft Learn page yet. | Re-run the verifier (`skill/references/checklists/`) in an environment with open web access, or clone `MicrosoftDocs` repositories over git if available. |
| B-002 | Homebrew tap integration deferred (user decision): `gh` is not usable in this container. | Release workflow contains the tap job but it is skipped until `HOMEBREW_TAP_TOKEN` exists. | Create a fine-grained PAT with `contents: write` on `0xRD/homebrew-tap`, then `gh secret set HOMEBREW_TAP_TOKEN -R 0xRD/forensic-hunter`. Fallback: `scripts/update-tap.sh` with a local `gh` login. |
| B-003 | `brew search forhunt` could not be run (no Homebrew, API blocked). | Name clash in Homebrew core unverified. | Run `brew search forhunt` once on a Mac. |
| B-004 | EvtxECmd cannot be benchmarked here: the .NET runtime and Eric Zimmerman's download site are unreachable from the build container. | No EvtxECmd column in the README benchmark table. | Run `EVTXECMD=/path/EvtxECmd.dll scripts/bench.sh` on a machine with `dotnet`. |
