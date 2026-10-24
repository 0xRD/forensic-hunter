# Blockers

Items that need a human or a different environment. Work continues around them.

| # | Blocker | Impact | What is needed |
|---|---------|--------|----------------|
| B-001 | The build container's network allows only GitHub (git and raw.githubusercontent.com). learn.microsoft.com, attack.mitre.org, JPCERT/CC, SANS, The DFIR Report, NSA, ANSSI, crates.io API and formulae.brew.sh are unreachable. | Checklist `verified` flags rest on GitHub-hosted sources (SigmaHQ, Hayabusa, Chainsaw, Microsoft Sysmon docs source, MITRE CTI data, JPCERT ToolAnalysisResultSheet repo). No check is confirmed against a Microsoft Learn page yet. | Re-run the verifier (`skill/references/checklists/`) in an environment with open web access, or clone `MicrosoftDocs` repositories over git if available. |
| B-002 | ~~Homebrew tap integration deferred.~~ **Resolved 2026-10-24:** `Formula/forhunt.rb` is in `0xRD/homebrew-tap`; the release job pushes with the `TAP_DEPLOY_KEY` secret (D-043). | - | - |
| B-003 | ~~`brew search forhunt` not run.~~ **Resolved 2026-10-24:** no clash; `brew audit --strict --online` passes and `brew install 0xrd/tap/forhunt` works on macOS arm64. | - | - |
| B-004 | EvtxECmd cannot be benchmarked here: the .NET runtime and Eric Zimmerman's download site are unreachable from the build container. | No EvtxECmd column in the README benchmark table. | Run `EVTXECMD=/path/EvtxECmd.dll scripts/bench.sh` on a machine with `dotnet`. |

## B-005 — tag push refused from the build session (worked around)
`git push origin v0.1.0` returns HTTP 403 from the session's git proxy while
branch pushes work. Workaround: Actions -> Release -> Run workflow with
`tag: vX.Y.Z` (D-035). From a normal machine, `git push origin vX.Y.Z` works.
