# Changelog

All notable changes to the `out-writ-examples` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This crate is not published to crates.io (`publish = false`); versions track
the workspace.

## [0.1.0] - Unreleased

### Added
- `guarded-counter-server`: a real `rmcp` stdio MCP server whose tools sit
  behind a guard derived from their own `.telos` service contract (compiled
  at boot via `StaticAgent`; startup aborts if anything fails to verify).
  Tool surface: proved-`Pure` `noop`, proved-monotone `bump` (conservatively
  `Write{"*"}`), unproved `delete_everything` (always denied), and a
  `grants` introspection helper printing the enforced capability table.
  Denials carry the enriched held-vs-attempted text prefixed
  `WRIT DENIED:`.
- `agent-demo`: the spec release-checklist run — an external agent making
  one allowed call set (`noop`, `bump n=41`, `bump n=1`) and one refused
  call (`delete_everything`) against the guarded server.
- `StdioMcpClient`: minimal MCP client over newline-delimited JSON-RPC on a
  spawned child's stdio — none of rmcp's client machinery in between — plus
  the `tool_text` result extractor.
- End-to-end tests driving the actual server binary over its real stdio
  transport: an allowed call reaches the real handler; a disallowed call
  comes back denied. No mocks.
