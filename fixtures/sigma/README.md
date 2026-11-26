# Sigma test rules

Rules written for forhunt's own tests (MIT OR Apache-2.0, like the rest of
the repository). No third-party rule is committed: the Hayabusa / SigmaHQ
rule sets are downloaded by the user (`skill/scripts/install.sh`).

- `rules/`: valid rules over `fixtures/synthetic` and `fixtures/prefetch`.
- `broken/`: one rule that does not compile and one deprecated rule, to
  check they are reported, not silently dropped.
