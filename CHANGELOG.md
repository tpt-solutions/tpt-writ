# CHANGELOG

All notable changes to tpt-writ are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
Semantic Versioning.

## [0.1.0] - Unreleased

### Added
- `tpt-writ-core`: the MCP right vocabulary (`WritRight`: scoped `Read`,
  scoped `Write`, `Pure`), `WritGrant`, the `RightDerivation` trait, and the
  conservative fail-closed derivation. The VALIDATE step reuses
  `tpt_telos_codegen::proof::verify_manifest` directly for hash re-derivation
  and tamper detection — no validator reimplementation, and no
  `tpt-nexus-manifest-validator` dependency by explicit non-goal. Also ships
  the missing reader half of the manifest format (`parse_manifest_json`).
- `tpt-writ-mcp`: `WritGuard` — loads a validated (and optionally
  ed25519-signed) manifest, derives one grant per verified function, and
  answers `check_call(tool, resource_class, mode)` with either pass-through
  or an enriched `WritDenied` stating what was held vs. what was attempted.
  Transport-agnostic: knows nothing about rmcp or JSON-RPC.
- `out-writ-examples`: a real `rmcp` stdio MCP server whose tools sit behind
  a guard derived from their own `.telos` service contract (compiled at boot
  via `StaticAgent`), plus an agent demo making one allowed and one denied
  call, plus end-to-end tests driving the actual server binary over its
  stdio transport.
- `tpt-writ-cli` (`writ`):
  - `verify <service.telos>` — compile via `tpt_telos_sdk::compile`, derive
    grants, print the MCP grant table;
  - `guard --manifest <telos-proof.json> [--source | --pubkey/--signature]
    --target <mcp-server> [—target-arg …]` — spawn a running MCP server and
    relay its tool calls through a `WritGuard`, answering denied calls
    in-flight without forwarding them;
  - `diff <before.telos> <after.telos>` — exit 0 on no change or narrowing,
    exit 1 on widening (new Write, Pure -> Read/Write, new function earning
    access);
  - `doctor` — toolchain and sibling-checkout environment check.
- Independent ed25519 signing module shaped like nexus's `Keypair` /
  `sign` / `verify` — same mental model, zero `tpt-nexus-cli` dependency.
- Repository scaffolding: workspace `Cargo.toml`, dual MIT/Apache-2.0
  licenses, CI (fmt/clippy/test against the checked-out `tpt-telos` sibling
  plus an MSRV job for the core crate), README with the position-in-stack
  diagram, `.telos` fixtures including a widening pair for `diff`.
- Per-crate documentation: every crate ships its own `README.md` (usage,
  API surface, decision tables) and `CHANGELOG.md`, and declares
  crate-specific crates.io keywords and categories instead of inheriting
  shared workspace-wide ones.

### Deliberately deferred
- Resource-class-aware derivation (`ResourceAwareDerivation`): gated on
  upstream `tpt-telos-parser` gaining string-literal args and
  `tpt-telos-ir` gaining resource-class provenance — tracked as Phase 4 in
  `todo.md`, to be contributed upstream rather than reimplemented here. The
  `RightDerivation` trait boundary is already in place so the swap requires
  zero changes downstream.
