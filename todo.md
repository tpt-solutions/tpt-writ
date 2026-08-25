# tpt-writ — Build Checklist

Proof-gated capability guard for MCP tool calls. See `spec.txt` for full design.
Dual-licensed MIT OR Apache-2.0, © 2026 TPT Solutions.

Non-goal reminder: **no `tpt-writ-*` crate ever depends on a `tpt-nexus-*` crate,
and vice versa.** Where the spec says "reuse Nexus's X," this checklist reuses
the underlying `tpt-telos` logic directly instead, or reimplements a small
equivalent — never a `tpt-nexus-*` path dependency.

---

## Phase 0 — Repo & workspace scaffolding

- [x] `git init` at `c:/Programming/2 WIP/tpt-writ` (repo initialized; no
      commits yet — everything below is still untracked working tree)
- [x] Root `Cargo.toml` workspace: `resolver = "2"`, `edition = "2021"`,
      `rust-version = "1.74"`, `[workspace.package] license = "MIT OR Apache-2.0"`
- [x] `LICENSE-MIT` (Copyright (c) 2026 TPT Solutions)
- [x] `LICENSE-APACHE` (2026 TPT Solutions)
- [x] `.gitignore` (`/target`, `/out`, `*.jsonl`, etc. — mirror `tpt-nexus`)
- [x] `.github/workflows/ci.yml` — fmt check, `clippy -D warnings`,
      `cargo test --workspace`, MSRV (1.74) check; check out sibling
      `tpt-telos` repo for path deps, matching `tpt-nexus`'s CI pattern
      (note: its `verify-examples` job runs `writ verify examples/counter.telos`
      and `writ doctor`, which don't exist yet — see Phase 3)
- [x] README skeleton: title/tagline, position-in-stack diagram (from spec),
      crate table, "Why this, why now" section
- [x] Confirm/document sibling checkout layout: `tpt-telos-sdk` resolved via
      `{ path = "../tpt-telos/crates/tpt-telos-sdk" }` (same convention as
      `tpt-nexus`) — requires `tpt-telos` checked out as a sibling directory
      in dev and CI (confirmed present at `../tpt-telos`; documented in
      Cargo.toml comments and README "Prerequisites")

## Phase 1 — `tpt-writ-core`: right vocabulary & conservative derivation ✅ done

- [x] `WritRight` enum: `Read { resource_class: String }`,
      `Write { resource_class: String }`, `Pure`
- [x] `WritGrant` struct: `function_name`, `right`, `manifest_hash: [u8; 32]`, `issued_at`
- [x] `RightDerivation` trait: `derive(&self, manifest: &ProofManifest, function: &str) -> WritGrant`
- [x] `ConservativeDerivation` impl — fail-closed: anything not provably `Pure`
      derives `Write { resource_class: "*" }`
- [x] VALIDATE-step integration: depends directly on
      `tpt_telos_codegen::proof::verify_manifest` (via `tpt-telos-sdk`/
      `tpt-telos-codegen` path deps) for hash re-derivation + tamper detection
      — **not** `tpt-nexus-manifest-validator` (`crates/tpt-writ-core/src/validate.rs`)
- [x] Unit tests: derivation correctness (Pure vs. fallback), manifest-hash
      tamper detection (mutated manifest → rejected) — 12 tests in
      `tpt-writ-core/src/tests.rs`, all passing

## Phase 2 — `tpt-writ-mcp`: MCP interceptor ✅ done

- [x] `WritGuard<D: RightDerivation>` struct: `derivation: D`,
      `grants: BTreeMap<String, WritGrant>` (`BTreeMap` instead of `HashMap`,
      for deterministic grant-table ordering)
- [x] `WritGuard::from_manifest(manifest: &ProofManifest, derivation: D) -> Self`
      plus `WritGuard::from_signed_manifest(json, pubkey, sig, derivation) ->
      Result<Self, WritGuardError>` for the signature-validating load path —
      populates grants via `D::derive`
- [x] `WritGuard::check_call(tool_name, resource_class, mode: AccessMode) -> Result<(), WritDenied>`
- [x] `WritDenied` type — enriched denial showing grant held vs. access attempted
      (mirrors Archon's `CacheError::Denied` clarity, independently defined here)
- [x] Minimal example MCP server built on `rmcp`
      (`crates/out-writ-examples/src/bin/guarded_counter_server.rs`)
- [x] Wrap that server's tool dispatch with `WritGuard::check_call` as a thin
      decorator (no fork of the server)
- [x] End-to-end test against the real example server (not a mock): allowed
      call passes through, disallowed call is denied with correct `WritDenied`
      (`crates/out-writ-examples/tests/e2e.rs`, drives the real binary over
      stdio JSON-RPC) — passing

## Phase 3 — `tpt-writ-cli` ✅ done

- [x] Independent `ed25519-dalek`-based signing module
      (`crates/tpt-writ-cli/src/signing.rs`)
- [x] `writ verify service.telos` — compile via `tpt_telos_sdk`, derive
      grants, print derived MCP grant table
- [x] `writ guard --manifest ... --target <mcp-server-program>` — start
      guarding a running MCP server via `WritGuard` (`src/guard.rs` +
      `src/relay.rs`; the flag is `--target <program>` with repeatable
      `--target-arg`, not a socket path as originally sketched — the guard
      spawns and relays stdio, it doesn't attach to a running process)
- [x] `writ doctor` — environment/dependency check (`src/doctor.rs`)
- [x] `writ diff before.telos after.telos` — exit 0/1 per widening
      (`src/diff.rs`); exit 2 added for "a source failed to compile"
- [x] CLI tests: `crates/tpt-writ-cli/tests/cli_e2e.rs` (5 tests: doctor,
      verify, diff both directions, guard's fail-closed trust gate) +
      `tests/relay_roundtrip.rs` — all passing
- [x] `examples/counter.telos` + `examples/counter-v2.telos` fixtures exist
      and are what the CLI tests and CI's `verify-examples` job use

## Phase 4 — `ResourceAwareDerivation` ✅ done

Full implementation across both repos (see the design-decision notes below —
two deviations from this checklist's original wording, both deliberate):

- [x] **Deviates from the original wording**: rather than adding a
      *bare positional* string `Arg` variant, `tpt-telos-parser` gained a
      `Literal::Str(String)` variant used through the existing `key = value`
      shape — syntax is `@resource(class = "db:users")`, not a bare
      `@resource("db:users")`. Smaller grammar surface, no new `Arg` variant.
      Also added: attributes were previously rejected on `invariant`/`struct`
      items entirely; the parser now accepts `@resource(...)` there
      specifically (every other attribute name is still rejected on those
      item kinds, unchanged). New `Token::Str`/string-literal lexer support.
      (`tpt-telos-parser/src/{lexer,ast,parser}.rs`, `grammar.ebnf`; new
      tests in `tests/{lexer,parser}.rs`)
- [x] **Turned out simpler than scoped**: resource-class tracking is a
      *derived static fact*, not a new SMT proof obligation — no changes
      needed to `tpt-telos-verifier`'s entailment logic. `tpt-telos-ir`'s
      existing per-function field-reference/assignment analysis (previously
      computed only to generate frame axioms, then discarded) is now
      surfaced as `VerificationProblem::resource_accesses:
      BTreeMap<String, AccessMode>`, resolving each touched field's base
      variable to its declared type's `@resource(...)` tag.
      (`tpt-telos-ir/src/{ir,extract}.rs`; new tests in `tests/extract.rs`)
      Threaded through `tpt-telos-codegen`'s `FuncProof`/`to_json`
      (`tpt-telos-ir` promoted from dev- to a real dependency there) — new
      tests in `src/proof.rs`.
- [x] `tpt-writ-core::ResourceAwareDerivation` — narrows single-tagged-class
      functions to `Read{class}`/`Write{class}`; still fails closed to
      `Write{"*"}` for untagged or multi-class functions (v0.1's `WritRight`
      has no "class A and class B" variant). 8 unit tests in `src/tests.rs`.
      `tpt-writ-core/src/validate.rs`'s manifest mirror updated to carry
      `resource_accesses` (`#[serde(default)]`, so pre-Phase-4 manifests
      still parse). `tpt-telos-ir` added as a real dependency of
      `tpt-writ-core` (re-exports `AccessMode` for downstream consumers).
- [x] Swap-in verification: `tpt-writ-mcp/src/tests.rs` builds two
      `WritGuard`s from the *same* manifest (`ConservativeDerivation` vs.
      `ResourceAwareDerivation`) through the identical `check_call` path.
      `tpt-writ-cli`'s `derive_rights` was split into a derivation-generic
      `derive_rights_with<D>` (used by the v0.1 default `derive_rights`) —
      proven in `src/lib.rs`'s new test module against a real multi-class
      fixture, zero structural changes to either crate.
- [x] Extended `writ diff` test: `diff.rs`'s `classify`/`any_widening` needed
      **no changes at all** (already fully generic over resource classes).
      New fixtures `examples/multi_resource.telos` /
      `-v2.telos` (a `Sender`/`Receiver`/untagged-`Ledger` example covering
      all four derivation outcomes) prove a resource-class narrowing/widening
      that `ConservativeDerivation` cannot see at all.

## Phase 5 — Polish & release readiness

- [x] End-to-end example: a `.telos` service + guarded example MCP server +
      an agent making one allowed and one denied tool call — satisfied today
      by `guarded_counter_server` + `out-writ-examples/tests/e2e.rs` (the test
      itself plays the agent, via `mcp_client::StdioMcpClient`). Still open:
      `crates/out-writ-examples/src/bin/agent_demo.rs` is a `fn main() {}`
      stub — README's "Crates" table already advertises a standalone runnable
      "agent demo" binary distinct from the test, so that's still owed.
- [x] `CONTRIBUTING.md` (68 lines), `CHANGELOG.md` (55 lines) — exist; not
      deeply reviewed for content quality, just confirmed present and
      non-trivial.
- [ ] `cargo publish --dry-run` across `tpt-writ-core`, `tpt-writ-mcp`,
      `tpt-writ-cli` — **not run**; likely to fail as-is since these crates
      depend on `tpt-telos-sdk`/`-codegen`/`-ir` via unpublished path deps
      with no crates.io fallback, which `cargo publish` can't resolve. Not
      attempted this session (a dry-run was declined) — worth a real pass
      once `tpt-telos` has crates.io releases to point at, or with
      `--no-verify` accepted as a known limitation until then.
- [x] `cargo tree` audit confirming zero `tpt-nexus-*` crates anywhere in the
      dependency graph (non-goal check) — verified clean:
      `cargo tree --workspace | grep tpt-nexus` returns nothing
