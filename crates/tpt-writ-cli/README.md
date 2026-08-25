# tpt-writ-cli

**`writ` — verify, guard, diff, and doctor `.telos`-backed MCP guards.**

Part of the [tpt-writ](https://github.com/TPT-Org/tpt-writ) workspace.
Deliberately mirrors nexus's CLI naming so the mental model transfers: same
verbs, different target — MCP tool-call scopes instead of Archon page
capabilities.

## Prerequisites

Builds against the sibling repo it consumes as a local path dependency
(see the workspace README's *Prerequisites*):

```text
<parent>/tpt-telos     # provides crates/tpt-telos-sdk
<parent>/tpt-writ      # you are here
```

`writ doctor` checks exactly this layout before anything else.

## Build

```sh
cargo build -p tpt-writ-cli
target/debug/writ --help
```

## `writ verify <service.telos>`

Compile via `tpt_telos_sdk::compile`, derive grants from the attested proof,
print the MCP grant table:

```text
$ writ verify examples/counter.telos
examples/counter.telos: 2/2 functions verified

MCP grants derived from the attested proof:
  noop  Pure
  bump  Write(*)
```

Exit codes: `0` = all functions verified · `1` = pipeline failure or any
unverified function (its name is printed; it earns no grant).

## `writ guard`

Spawn a running MCP server and relay its traffic through a
[`WritGuard`](../tpt-writ-mcp/README.md): agent-side stdio in,
newline-delimited JSON-RPC forwarded — **except** `tools/call` requests,
which are checked first. Denied calls never reach the target; they go back
to the agent in-flight as an MCP tool result with `isError: true`, carrying
the enriched held-vs-attempted text.

```text
writ guard --manifest telos-proof.json \
           [--source service.telos | --pubkey <hex> --signature <hex-or-file>] \
           --target <mcp-server> [--target-arg <arg>]... \
           [--allow-tool <name>]...
```

| Flag | Role |
|---|---|
| `--manifest` | The `telos-proof.json` document to enforce |
| `--source` | `.telos` bytes enabling the full VALIDATE (hash) check |
| `--pubkey` + `--signature` | ed25519 authorship gate when the source is unavailable; the signature may be hex or a path to a file containing hex |
| `--target` / `--target-arg` | The MCP server process to spawn and guard, with repeatable arguments |
| `--allow-tool` | Tools whose calls are existence-checked only — the right policy for `Pure` tools |

At least one trust gate (`--source` **or** `--pubkey/--signature`) is
required. Startup prints which gate(s) accepted the manifest plus the
enforced grant table.

Exit codes: `0` = clean shutdown · `1` = manifest rejected, spawn failure,
or relay error.

This is how a server you *cannot* recompile gets guarded: `writ guard`
spawns it as a child and relays its traffic. Servers you *can* recompile
embed the guard directly at dispatch instead (see
[`out-writ-examples`](../out-writ-examples/README.md)).

## `writ diff <before.telos> <after.telos>`

The capability security-regression view — same question as
`nexus diff`: did the resource-access surface widen?

```text
$ writ diff examples/counter.telos examples/counter-v2.telos
capability surface examples/counter.telos -> examples/counter-v2.telos:
  = noop: unchanged
  = bump: unchanged
  ! +reset: new access right (WIDENED)

VERDICT: WIDENED — this change grants more than before
```

Exit codes: `0` = no change or a narrowing · `1` = a widening (a new
`Write`, `Pure` → `Read`/`Write`, or a new function earning access) ·
`2` = a source failed to compile (cannot compare).

Wire it into CI to fail merges whose contract grew more permissive.

## `writ doctor`

Toolchain and sibling-checkout environment check before a build: `cargo` /
`rustc` on PATH, the `../tpt-telos` sibling present with
`crates/tpt-telos-sdk`, and the `telos-codegen` proof module. Exit `0` =
healthy · `1` = fix the FAIL lines first.

## Signing attestations

An independently implemented ed25519 module shaped like nexus's
`Keypair` / `sign` / `verify` — same mental model, zero `tpt-nexus-cli`
dependency. The manifest's internal hashes prove the document matches its
source; anyone can still regenerate both for edited code. A signature over
the exact manifest document, made with a project key, closes that:
`writ guard` trusts a manifest only when it carries a signature from a key
the deployment trusts. Keys never travel inside the manifest.

```rust
use tpt_writ_cli::signing::Keypair;

let key = Keypair::generate();
let sig = key.sign(manifest_json.as_bytes());
assert!(tpt_writ_cli::signing::verify(
    &key.public_hex(), manifest_json.as_bytes(), &sig));
```

## More than a binary

All logic lives in the library crate (`tpt_writ_cli`) for testability and
reuse in your own tooling:

- `compile_service` / `derive_rights` / `format_right_table` — the verify
  pipeline as data;
- `guard::{load_manifest, spawn_target, build_guard}` — trust-gate loading
  shared by any embedder;
- `relay::{Relay, GuardPolicy, Attempt}` — build your own guarded proxy:
  per-tool attempt policies (`Attempt::Exists` for pure tools, concrete
  `Attempt::Access { class, mode }`) with a fail-closed default
  (`Access { "*", Write }`), which under v0.1's conservative derivation
  enforces exactly the attested-tool allowlist.

## License

Dual-licensed under MIT OR Apache-2.0 — see
[LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
© 2026 TPT Solutions.
