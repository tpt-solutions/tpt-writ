# Contributing to tpt-writ

Thanks for wanting to improve the proof-gated MCP capability guard. This
document is the human-facing companion to the repo's `spec.txt` and `todo.md`.

## What writ is

`writ` is a *thin* enforcement layer. It does **not** reimplement a verifier,
an attestation format, or a hash scheme. It consumes the `ProofManifest`
produced by `tpt_telos_sdk::compile`, derives one minimal MCP right per
proved function, and refuses any tool call that oversteps its grant. The hard
rules that follow:

- **No `unsafe`.** Anywhere in any `tpt-writ-*` crate.
- **Reuse the real crates.** Build against the local sibling `../tpt-telos`
  path dependency. Do not vendor it and do not invent APIs that already exist
  upstream.
- **Never depend on `tpt-nexus-*`** — and vice versa. Same upstream input,
  different downstream target; if a nexus dependency ever feels necessary,
  that is scope drift (spec §6) and should be reconsidered, not implemented.
- **Fail closed.** Anything not provably narrow falls back to the coarsest
  restrictive right (`Write { "*" }`) or to no grant at all. Every change to
  derivation or enforcement needs a test showing the fail-closed behavior.

## Getting set up

1. Clone both repos as siblings of the same parent directory:
   `tpt-telos`, `tpt-writ`.
2. Build and test: `cargo test --workspace`.
3. Sanity-check the pipeline: `cargo run -p tpt-writ-cli -- doctor`.

## Before you open a PR

Run the same gate CI runs:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

A green local run is a strong signal.

## What makes a good change

- **Bug fixes** come with a regression test.
- **Enforcement must be enforced, not cosmetic.** If you touch `check_call`,
  the relay's decision path, or the example server's decorators, prove via a
  test that denials actually happen and reach the caller with the enriched
  held-vs-attempted text.
- **Derivation changes are security-boundary changes.** The v0.1 posture is
  deliberately coarse; narrowing it before upstream resource-class tracking
  exists would be over-granting by inference. Propose such work as an
  upstream `tpt-telos` contribution first (see Phase 4 in `todo.md`).
- Keep the trait boundary honest: `tpt-writ-mcp` must keep working unchanged
  when `ConservativeDerivation` is swapped for another `RightDerivation`.
- Add your change to `todo.md` (mark the item done) and, if user-facing, to
  the CHANGELOG.

## Commit / PR style

- Keep commits focused; one logical change per commit.
- PRs should explain the *why*, link the relevant `todo.md` item, and include
  the output of the three-command gate above.

## License

By contributing you agree your work is dual-licensed under MIT OR Apache-2.0.
