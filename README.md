# tpt-writ

**The proof-gated capability guard for MCP tool calls.** Same mechanism as
[`tpt-nexus`](https://github.com/TPT-Org/tpt-nexus)'s proof→capability
derivation, re-targeted at a different boundary: instead of minting an Archon
memory-page right, it mints an **MCP tool-call scope**, and checks it before
letting an external agent's tool call through.

`tpt-telos` turns intent into verified code and a signed attestation. Nexus
proved that a verified program earns *exactly* the memory rights its proof
implies — but wired to one consumer (Archon) and one right vocabulary (page
capabilities). `tpt-writ` re-aims that one Archon-specific piece at MCP, which
is already the interop surface for `tpt-locus`, `tpt-anima`, and any external
agent framework.

```
                    (unchanged, reused as-is)
┌──────────────┐  ProofManifest   ┌──────────────────┐
│ tpt-telos-sdk│ ───────────────▶ │  tpt-writ-core   │
│ compile()    │                  │  right derivation │
└──────────────┘                  │  (MCP vocabulary) │
                                   └─────────┬────────┘
                                             │ WritGrant
                                             ▼
                                   ┌──────────────────┐      MCP tool call
                                   │ tpt-writ-mcp     │◀───────────────────
                                   │  interceptor     │      from any agent
                                   └─────────┬────────┘
                                             │ allow / deny
                                             ▼
                                   ┌──────────────────┐
                                   │  wrapped MCP tool │
                                   │  (any server)     │
                                   └──────────────────┘
```

No `tpt-nexus-*` crate appears in that diagram anywhere, and none ever will be
a dependency of a `tpt-writ-*` crate (or vice versa). Same upstream input
(`ProofManifest` from `tpt_telos_sdk::compile`), different downstream target.

## Why this, why now

Nexus already proved the hard part works: verify a program against
`requires`/`ensures` contracts, attest the result, derive a minimal right from
*what the proof showed the function does*, and refuse anything that oversteps.
Everything generic — the verifier, the attestation format, the anti-tamper
manifest check, ed25519 signing — already exists upstream in `tpt-telos`. The
only consumer-specific piece was `derive_rights`, and `tpt-writ` supplies its
own equivalent for the MCP vocabulary rather than reaching back into nexus.

A proof-gated guard sitting in front of an MCP tool call is useful to agents
that have never heard of the rest of the TPT stack: MCP is the wire format they
already speak.

## Crates

| Crate | Role |
|-------|------|
| [`tpt-writ-core`](crates/tpt-writ-core/README.md) | The MCP right vocabulary (`WritRight`), `WritGrant`, the `RightDerivation` trait, and the conservative fail-closed derivation. Knows proofs and rights; knows nothing about MCP. ([changelog](crates/tpt-writ-core/CHANGELOG.md)) |
| [`tpt-writ-mcp`](crates/tpt-writ-mcp/README.md) | `WritGuard`: loads a validated, signed manifest, derives grants per function, and answers *one question*: is this tool call allowed? Denials are enriched with what was held vs. what was attempted. ([changelog](crates/tpt-writ-mcp/CHANGELOG.md)) |
| [`tpt-writ-cli`](crates/tpt-writ-cli/README.md) (`writ`) | `verify` / `guard` / `diff` / `doctor` — deliberately mirrors `nexus verify`/`nexus diff` naming so the mental model transfers. ([changelog](crates/tpt-writ-cli/CHANGELOG.md)) |
| [`out-writ-examples`](crates/out-writ-examples/README.md) | A real `rmcp` stdio MCP server whose tools sit behind a `WritGuard`, plus an agent demo making one allowed and one denied call, plus the end-to-end tests. ([changelog](crates/out-writ-examples/CHANGELOG.md)) |

## The v0.1 posture: fail closed

Resource-class tracking does not exist yet in `tpt-telos-ir` (it is scoped as
an upstream contribution, not a downstream reimplementation). Until then,
derivation is deliberately coarse: any function that isn't provably free of
resource interaction derives the single most restrictive coarse right,
`Write { resource_class: "*" }` — under-granting nothing, never over-granting.
The `RightDerivation` trait exists from day one so the future
resource-aware derivation swaps in without touching `tpt-writ-mcp` at all.

## Prerequisites

Builds **against the sibling repo it consumes** as a local path dependency —
nothing here is published to crates.io yet. Clone both repos as siblings of
the same parent directory:

```
<parent>/tpt-telos     # provides crates/tpt-telos-sdk (and its workspace deps)
<parent>/tpt-writ      # you are here
```

Rust 1.74+ for `tpt-writ-core`; the MCP example server tracks current stable
(its `rmcp` dependency does).

## Quickstart

```text
cargo run -p tpt-writ-cli -- doctor                          # environment check
cargo run -p tpt-writ-cli -- verify examples/counter.telos   # compile + derive grant table
cargo test  -p out-writ-examples                             # e2e: guarded rmcp server over stdio JSON-RPC
```

## License

Dual-licensed under MIT OR Apache-2.0 — see `LICENSE-MIT` and
`LICENSE-APACHE`. © 2026 TPT Solutions.
