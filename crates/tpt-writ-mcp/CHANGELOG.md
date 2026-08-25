# Changelog

All notable changes to the `tpt-writ-mcp` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added
- `WritGuard<D: RightDerivation>` — loads a validated manifest and derives
  one grant per verified function through `tpt-writ-core`:
  - `from_manifest` for callers that produced the manifest via
    `tpt_telos_sdk::compile` or already ran
    `tpt_writ_core::validate_manifest` on the serialized form;
  - `from_signed_manifest` with two independent gates, both required —
    ed25519 authorship over the exact document bytes, plus well-formedness
    of the embedded hash fields.
- `check_call(tool, resource_class, mode)`: either pass-through or an
  enriched `WritDenied` stating what was held vs. what was attempted. Full
  decision table over the v0.1 conservative vocabulary: `Write{"*"}`
  allows everything; scoped rights match class and mode; `Pure` denies any
  resource access; unknown tools deny `NoGrant`.
- `check_tool(tool)`: existence-only check — the right question for tools
  whose handlers perform no resource interaction (`Pure` tools).
- Enriched denials mirroring Archon's `CacheError::Denied` clarity,
  independently defined here — no `tpt-archon-*` dependency.
  `DenialReason` covers `NoGrant`, `PureHoldsNoResourceAccess`,
  `WrongResourceClass`, `ReadHeldForWriteAttempt`.
- Introspection: `grants()` (enforced table keyed by tool name),
  `manifest_hash()` (hash every grant was derived from), `derivation()`.
- `WritGuardError`: load-time failures (`InvalidSignature`, `Manifest`)
  kept separate from call-time denials.
- Transport-agnostic by design: knows nothing about rmcp or JSON-RPC. Wrap
  an `rmcp` server as a thin decorator at dispatch (see
  `out-writ-examples`), or sit inside `writ guard`'s stdio relay for
  servers that cannot be recompiled. Never forks a server implementation.
