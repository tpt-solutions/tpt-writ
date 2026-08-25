# Changelog

All notable changes to the `tpt-writ-core` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added
- The MCP right vocabulary (`WritRight`): scoped
  `Read { resource_class }`, scoped `Write { resource_class }`, and `Pure`,
  with `Display` renderings (`Read(fs:/data)`, `Write(db:users)`, `Pure`).
- `WritGrant`: function name, derived right, the SHA-256 of the attested
  manifest it was derived from (so a stale grant is detectable against a
  re-issued manifest), and an issuance timestamp.
- The `RightDerivation` trait — a boundary from day one so the future
  resource-aware derivation swaps in without touching `tpt-writ-mcp`.
- `ConservativeDerivation`, the v0.1 fail-closed derivation: a verified
  proof carrying zero conclusions derives `Pure`; everything else falls
  back to the single most restrictive coarse right,
  `Write { resource_class: "*" }`.
- `derive_all`: grants for every *verified* function in a manifest; failed
  proofs earn no grant.
- VALIDATE step (`validate_manifest`): reuses
  `tpt_telos_codegen::proof::verify_manifest` directly for hash
  re-derivation and tamper detection — no validator reimplementation, and
  no `tpt-nexus-manifest-validator` dependency by explicit non-goal. Also
  reports embedded-vs-recomputed hashes so humans can see what disagrees.
- `parse_manifest_json`: the missing reader half of the generator's
  write-only manifest format; anything the generator would not have
  written is rejected.
- `manifest_hash_bytes` / `try_manifest_hash_bytes`: decode the
  `sha256:<64 hex>` field into raw bytes (panicking and fallible
  variants).
- `WritError`: `ManifestTampered`, `SourceDrift`, `MissingManifestHash`,
  `MalformedManifestHash`, `MalformedManifest`.

### Deliberately deferred
- Resource-class-aware derivation (`ResourceAwareDerivation`): gated on
  upstream `tpt-telos-parser` gaining string-literal args and
  `tpt-telos-ir` gaining resource-class provenance — tracked as Phase 4 in
  `todo.md`, to be contributed upstream rather than reimplemented here. The
  `RightDerivation` trait boundary is already in place so the swap requires
  zero changes downstream.
