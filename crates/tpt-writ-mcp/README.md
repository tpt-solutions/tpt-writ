# tpt-writ-mcp

**Proof-gated capability guard for MCP tool calls.**

Part of the [tpt-writ](https://github.com/TPT-Org/tpt-writ) workspace.
`WritGuard` loads a validated (and optionally ed25519-signed) proof
manifest, derives one capability grant per proved function through
[`tpt-writ-core`](../tpt-writ-core/README.md), and answers exactly one
question before any real handler runs: *allowed, or denied?*

The crate is deliberately transport-agnostic: it depends on `tpt-writ-core`
(proofs and rights) and on nothing MCP-shaped. Wrap an `rmcp` server as a
thin decorator at the dispatch entry point (see
[`out-writ-examples`](../out-writ-examples/README.md)), or let it sit inside
`writ guard`'s stdio relay for servers you cannot recompile. It never forks
a server implementation.

## Building a guard

Two constructors, matching the two trust gates a deployment can satisfy:

```rust
use tpt_writ_core::ConservativeDerivation;
use tpt_writ_mcp::WritGuard;

// Gate A: you produced the manifest yourself (or already ran
// tpt_writ_core::validate_manifest over the serialized form):
let guard = WritGuard::from_manifest(&artifact.manifest, ConservativeDerivation);

// Gate B: untrusted document + ed25519 authorship. Two independent gates,
// both required:
//   1. the signature verifies over the exact document bytes,
//   2. the embedded hash fields decode (the parse rejects anything the
//      generator would not have written).
let guard = WritGuard::from_signed_manifest(
    &manifest_json, &verifying_key, &signature, ConservativeDerivation,
)?;
```

Grants exist only for functions whose proofs **passed** — a failed proof
earns nothing, so any tool name absent from `guard.grants()` is denied at
check time.

## Deciding tool calls

`check_call(tool_name, resource_class, mode)` enforces the v0.1 decision
table:

| Held right | Attempted | Result |
|---|---|---|
| *(none)* | anything | deny `NoGrant` |
| `Write{"*"}` | any class, any mode | **allow** |
| `Write{c}` | class `c`, any mode | **allow** |
| `Read{c}` | read, class `c` | **allow** |
| `Pure` | anything | deny `PureHoldsNoResourceAccess` |
| `Read{c}` / `Write{c}` | other class | deny `WrongResourceClass` |
| `Read{c}` | write, class `c` | deny `ReadHeldForWriteAttempt` |

```rust
use tpt_writ_mcp::{AccessMode, WritGuard};

match guard.check_call("bump", "memory:counter", AccessMode::Write) {
    Ok(()) => forward_to_handler(),
    Err(denied) => return format!("WRIT DENIED: {denied}"),
}
```

Tools whose handler performs no resource interaction should be checked with
`check_tool(tool_name)` instead — it asks only *"is this tool attested?"*,
because a `Pure` tool never touches anything and would deny by construction
under `check_call`.

Introspection: `grants()` returns the enforced capability table,
`manifest_hash()` the hash every grant was derived from, and
`derivation()` the strategy in use.

## Enriched denials

Denials mirror Archon's `CacheError::Denied` clarity (independently defined
here — no `tpt-archon-*` dependency): `WritDenied` always states what was
attempted, what grant was held, and why the two do not fit.

```text
WRIT DENIED: denied `delete_everything`: attempted Write(*), but no grant
exists for this tool (absent from the attested proof, or its proof failed)
```

`DenialReason` covers `NoGrant`, `PureHoldsNoResourceAccess`,
`WrongResourceClass { held_class }`, and
`ReadHeldForWriteAttempt { resource_class }`. Load-time failures travel as
`WritGuardError` (`InvalidSignature`, `Manifest(_)`) — separate from
call-time denials.

## Swapping the derivation strategy

`WritGuard<D: RightDerivation>` is generic over the derivation from day
one: swapping `ConservativeDerivation` for a future resource-aware
derivation changes nothing in this crate or its consumers.

## License

Dual-licensed under MIT OR Apache-2.0 — see
[LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
© 2026 TPT Solutions.
