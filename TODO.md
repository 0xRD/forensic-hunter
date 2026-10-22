# Before making the repository public

Steps to run on a machine with `git`, `gh` (logged in as the repository
owner) and, for step 4, Homebrew. Do them in order: step 1 rewrites history,
so it must happen before anyone can clone or fork.

Repository: `0xRD/forensic-hunter`. Current release: `v0.1.0` (tag on
`833e577`, published by the Release workflow).

## 1. Put the owner's name on the commits

Every commit is currently authored as `Claude <noreply@anthropic.com>`.
Ask the owner which name and email to use, then:

```bash
git clone https://github.com/0xRD/forensic-hunter.git && cd forensic-hunter
pip install git-filter-repo        # or: brew install git-filter-repo
cat > /tmp/mailmap <<'EOF'
Owner Name <owner@example.com> Claude <noreply@anthropic.com>
EOF
git filter-repo --mailmap /tmp/mailmap --force
git log --format='%an <%ae> | %cn <%ce>' | sort | uniq -c   # check: only the owner remains
git remote add origin https://github.com/0xRD/forensic-hunter.git
git push --force origin master
```

The `Co-Authored-By: Claude ...` trailers in commit messages are kept (they
are part of the messages, not the author field).

## 2. Recreate the v0.1.0 release on the rewritten history

The old tag points at a commit that no longer exists on `master`.

```bash
gh release delete v0.1.0 --cleanup-tag --yes -R 0xRD/forensic-hunter
git tag -a v0.1.0 -m "forhunt 0.1.0" && git push origin v0.1.0
gh run watch -R 0xRD/forensic-hunter "$(gh run list -R 0xRD/forensic-hunter -w Release -L 1 --json databaseId -q '.[0].databaseId')"
gh release view v0.1.0 -R 0xRD/forensic-hunter --json assets -q '.assets[].name'
```

Expected assets (11): `forhunt-0.1.0-{x86_64,aarch64}-unknown-linux-musl.tar.gz`,
`forhunt-0.1.0-{x86_64,aarch64}-apple-darwin.tar.gz`,
`forhunt-0.1.0-x86_64-pc-windows-msvc.zip`, one `.sha256` per archive, and
`SHA256SUMS`.

## 3. Make the repository public

```bash
gh repo edit 0xRD/forensic-hunter --visibility public --accept-visibility-change-consequences
```

## 4. Homebrew tap (BLOCKERS.md B-002, B-003)

```bash
brew search forhunt                                   # name must be free
gh repo view 0xrd/homebrew-tap >/dev/null 2>&1 || gh repo create 0xrd/homebrew-tap --public -d "Homebrew formulae"
```

Create a fine-grained token with **Contents: read and write** on
`0xrd/homebrew-tap` only (github.com -> Settings -> Developer settings ->
Fine-grained tokens), then:

```bash
gh secret set HOMEBREW_TAP_TOKEN -R 0xRD/forensic-hunter   # paste the token
gh workflow run release.yml -R 0xRD/forensic-hunter -f tag=v0.1.0   # re-publishes v0.1.0 and runs the tap job
brew install 0xrd/tap/forhunt && forhunt --version && brew test forhunt
```

If the workflow is not wanted, `scripts/update-tap.sh v0.1.0` renders and
pushes the formula locally instead.

Then in `README.md`, replace "Homebrew (`brew install 0xRD/tap/forhunt`) is
coming." with a `brew install 0xRD/tap/forhunt` line in the install block.

## 5. Test the installers against the real release

```bash
bash skill/scripts/install.sh --prefix /tmp/fh-test     # forhunt + Hayabusa, checksums verified
/tmp/fh-test/bin/forhunt stats -q fixtures/synthetic/Security.evtx | head -3
/tmp/fh-test/bin/hayabusa help | head -3
bash skill/scripts/install.sh --prefix /tmp/fh-test2 --no-hayabusa   # "latest" resolution
```

Expected: `sha256 ok` for each download, `forhunt 0.1.0`, no Gatekeeper
prompt (curl downloads are not quarantined). On Windows (if available):
`powershell -ExecutionPolicy Bypass -File skill\scripts\install.ps1`.

## 6. Close out

Update `STATUS.md` (move these items to Done) and `BLOCKERS.md` (B-002, B-003
resolved), commit, push, and delete this file.
