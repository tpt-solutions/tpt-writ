# out-writ-examples

Runnable examples and end-to-end tests for
[tpt-writ](https://github.com/TPT-Org/tpt-writ). Not published to
crates.io — the `out-writ-` prefix marks crates that exist only to
demonstrate or exercise the publishable `tpt-writ-*` crates.

## What's inside

| Piece | Kind | What it shows |
|---|---|---|
| `guarded-counter-server` | binary | A real `rmcp` stdio MCP server whose every tool sits behind a `WritGuard` derived from its own `.telos` service contract |
| `agent-demo` | binary | An external agent making one allowed and one denied tool call against that server |
| `StdioMcpClient` | library | A minimal MCP client over newline-delimited JSON-RPC on a spawned child's stdio — exactly what any MCP client framework speaks |
| `tests/e2e.rs` | integration test | Drives the *actual* server binary over its real stdio transport — no mocks |

## `guarded-counter-server`

Boots by compiling its own `.telos` service contract (parse → verify →
attest, offline via `StaticAgent`), aborts startup if anything fails to
verify ("refusing to serve unproven tools"), derives one grant per proved
function, then consults the guard at the top of each tool's dispatch entry
— a thin decorator, not a fork of any server implementation.

Tool surface and provenance:

| Tool | `.telos` function | Derived right (v0.1 conservative) | Outcome |
|---|---|---|---|
| `noop` | `noop` | `Pure` (vacuous proof) | allowed (existence check) |
| `bump` | `bump` (proved monotone increase) | `Write{"*"}` fallback | allowed while the proof holds |
| `delete_everything` | — not in any proof — | no grant | **always denied** |
| `grants` | introspection helper | — | prints the enforced capability table |

Denied calls come back to the agent as tool output prefixed
`WRIT DENIED:` with the enriched held-vs-attempted text.

```sh
cargo run -p out-writ-examples --bin guarded-counter-server
```

## `agent-demo`

Spawns the guarded server, performs the MCP handshake, then runs the spec's
release-checklist sequence: `noop` (allowed), `bump n=41` and `bump n=1`
(allowed), `delete_everything` (refused) — ending with the summary line
*"allowed calls executed; the unproved call was refused"*.

```sh
cargo build -p out-writ-examples   # both binaries land in the same target dir
cargo run -p out-writ-examples --bin agent-demo
```

## End-to-end tests

```sh
cargo test -p out-writ-examples
```

`tests/e2e.rs` spawns the real `guarded-counter-server` binary and speaks
newline-delimited JSON-RPC to it over stdio: an allowed call passes through
to the real handler; a disallowed call comes back denied with the enriched
held-vs-attempted text.

## License

Dual-licensed under MIT OR Apache-2.0 — see
[LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
© 2026 TPT Solutions.
