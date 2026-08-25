# Changelog

All notable changes to the `tpt-writ-cli` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added
- `writ verify <service.telos>` — compile via `tpt_telos_sdk::compile`,
  derive grants, print the MCP grant table. Exit 0 only when every function
  verified; unverified names are printed and earn no grant.
- `writ guard --manifest <telos-proof.json> [--source |
  --pubkey/--signature] --target <mcp-server> [--target-arg …]
  [--allow-tool …]` — spawn a running MCP server and relay its tool calls
  through a `WritGuard`, answering denied calls in-flight without
  forwarding them (`isError: true` MCP tool results). At least one trust
  gate is required: full source-hash VALIDATE or an ed25519 authorship
  signature (bare hex or a path to a file containing hex).
- `writ diff <before.telos> <after.telos>` — capability security-regression
  view: exit 0 on no change or narrowing, exit 1 on widening (new Write,
  Pure -> Read/Write, new function earning access), exit 2 when a source
  fails to compile.
- `writ doctor` — toolchain and sibling-checkout environment check
  (`cargo`/`rustc` on PATH, `../tpt-telos` layout, telos-codegen proof
  module).
- Independent ed25519 signing module shaped like nexus's `Keypair` /
  `sign` / `verify` — same mental model, zero `tpt-nexus-cli` dependency.
  Keys never travel inside the manifest; malformed inputs verify as
  `false` so callers treat it uniformly as "do not trust".
- Library surface (all logic lives in the library for testability):
  - `compile_service` / `derive_rights` / `format_right_table` — the verify
    pipeline as data;
  - `guard::{load_manifest, spawn_target, build_guard}` — trust-gate
    loading shared by any embedder;
  - `relay::{Relay, GuardPolicy, Attempt}` — per-tool attempt policies
    (`Exists` for Pure tools, concrete `Access { class, mode }`) with a
    fail-closed default (`Access { "*", Write }`), plus in-flight denial
    responses that preserve the JSON-RPC id.
