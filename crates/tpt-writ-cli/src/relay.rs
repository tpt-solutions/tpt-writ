//! The guard relay: sit between an agent's stdio and a running MCP server's
//! stdio, forwarding everything except `tools/call` requests, which are
//! checked against a [`WritGuard`] first.
//!
//! This is how a server you *cannot* recompile gets guarded: `writ guard`
//! spawns it as a child and relays its traffic. The reference
//! `guarded-counter-server` instead embeds the guard directly at dispatch —
//! both are thin decorators, neither forks the server.
//!
//! Denials never reach the target. They go back to the agent as an MCP tool
//! result with `isError: true`, carrying the enriched held-vs-attempted text.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tpt_writ_mcp::{AccessMode, WritGuard};

/// What the relay pretends the agent is attempting when a given tool is
/// called. Enforcement compares this attempt against the held grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// Existence-only: the right question for tools holding `Pure`.
    Exists,
    /// A concrete resource access.
    Access {
        /// Resource class the call claims to touch.
        class: String,
        /// How it claims to touch it.
        mode: AccessMode,
    },
}

/// Per-tool attempt policy with a default for unlisted tools.
///
/// The default attempt is `Access { "*", Write }`: under v0.1's conservative
/// derivation every proved function holds `Write{"*"}` or `Pure`, so this
/// default enforces exactly the attested-tool allowlist (plus denying `Pure`
/// tools that claim writes). Scoped rights become meaningful together with
/// per-tool policies once resource-aware derivation lands.
#[derive(Debug, Clone)]
pub struct GuardPolicy {
    default_attempt: Attempt,
    per_tool: BTreeMap<String, Attempt>,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            default_attempt: Attempt::Access {
                class: "*".to_string(),
                mode: AccessMode::Write,
            },
            per_tool: BTreeMap::new(),
        }
    }
}

impl GuardPolicy {
    /// Override the attempt recorded for one tool.
    pub fn set(&mut self, tool: impl Into<String>, attempt: Attempt) -> &mut Self {
        self.per_tool.insert(tool.into(), attempt);
        self
    }

    fn attempt_for(&self, tool: &str) -> Attempt {
        self.per_tool
            .get(tool)
            .cloned()
            .unwrap_or_else(|| self.default_attempt.clone())
    }

    /// Decide a `tools/call` request: forward it, or deny it in-flight.
    pub fn decide<D: tpt_writ_core::RightDerivation>(
        &self,
        guard: &WritGuard<D>,
        request: &Value,
    ) -> Decision {
        let Some(name) = request["params"]["name"].as_str() else {
            return Decision::Deny("malformed tools/call request: missing params.name".to_string());
        };
        match self.attempt_for(name) {
            Attempt::Exists => match guard.check_tool(name) {
                Ok(()) => Decision::Forward,
                Err(d) => Decision::Deny(format!("WRIT DENIED: {d}")),
            },
            Attempt::Access { class, mode } => match guard.check_call(name, &class, mode) {
                Ok(()) => Decision::Forward,
                Err(d) => Decision::Deny(format!("WRIT DENIED: {d}")),
            },
        }
    }
}

/// The outcome of inspecting one request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Pass the line through to the guarded server untouched.
    Forward,
    /// Answer the agent here; the server never sees this call.
    Deny(String),
}

/// Craft the in-flight MCP result for a denied call (`isError: true`, so any
/// conforming client surfaces it as a failed tool call).
pub fn denial_response(request: &Value, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": {
            "content": [{"type": "text", "text": message}],
            "isError": true,
        },
    })
}

/// The wired-up relay over one guarded server process.
///
/// Agent side: read newline-delimited JSON-RPC, consult the policy, forward
/// allowed traffic, answer denied calls in-flight. Target side: a background
/// pump streams everything the server emits back to the agent untouched.
pub struct Relay<D: tpt_writ_core::RightDerivation> {
    pub guard: Arc<WritGuard<D>>,
    pub policy: GuardPolicy,
}

impl<D: tpt_writ_core::RightDerivation + 'static> Relay<D> {
    /// Serve until the agent closes its input stream, then hand the agent
    /// output buffer back (tests capture it; `writ guard` passes stdout and
    /// ignores the return).
    ///
    /// `agent_input`: bytes from the agent. `agent_output`: bytes to the
    /// agent (shared because both the request loop and the pump thread
    /// write). `target_input`: the child's stdin. `target_output`: the
    /// child's stdout.
    pub fn serve<A, AW, TI, TO>(
        &self,
        agent_input: A,
        agent_output: AW,
        target_input: TI,
        target_output: TO,
    ) -> anyhow::Result<AW>
    where
        A: std::io::Read,
        AW: std::io::Write + Send + 'static,
        TI: std::io::Write,
        TO: std::io::Read + Send + 'static,
    {
        let to_agent = Arc::new(Mutex::new(BufWriter::new(agent_output)));

        // Child -> agent passthrough.
        let backhaul_to_agent = Arc::clone(&to_agent);
        let pump = std::thread::spawn(move || {
            let reader = BufReader::new(target_output);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let mut out = backhaul_to_agent.lock().expect("agent writer mutex");
                if writeln!(out, "{line}").is_err() {
                    break;
                }
                if out.flush().is_err() {
                    break;
                }
            }
        });

        // Agent -> child, with interception.
        let mut target_writer = BufWriter::new(target_input);
        let mut reader = BufReader::new(agent_input);

        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break; // agent closed the stream
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let parsed: Option<Value> = serde_json::from_str(trimmed).ok();
            let is_tool_call = parsed
                .as_ref()
                .is_some_and(|msg| msg["method"] == "tools/call" && msg.get("id").is_some());

            if is_tool_call {
                let msg = parsed.as_ref().expect("checked above");
                match self.policy.decide(&self.guard, msg) {
                    Decision::Forward => {
                        writeln!(target_writer, "{trimmed}")?;
                        target_writer.flush()?;
                    }
                    Decision::Deny(message) => {
                        let response = denial_response(msg, &message);
                        let mut out = to_agent.lock().expect("agent writer mutex");
                        writeln!(out, "{response}")?;
                        out.flush()?;
                    }
                }
            } else {
                // Handshake, notifications, other methods: pass through.
                writeln!(target_writer, "{trimmed}")?;
                target_writer.flush()?;
            }
        }

        drop(target_writer); // close child stdin so it can exit
        let _ = pump.join();
        // All writers are gone by now; reclaim and unwrap the buffer.
        let writer = Arc::try_unwrap(to_agent)
            .map_err(|_| anyhow::anyhow!("agent writer still shared"))?
            .into_inner()
            .map_err(|e| anyhow::anyhow!("poisoned agent writer: {e}"))?;
        writer
            .into_inner()
            .map_err(|e| anyhow::anyhow!("final flush of agent output failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use tpt_telos_codegen::proof::{to_json, FuncProof, ProofManifest};
    use tpt_writ_core::ConservativeDerivation;

    fn manifest_with(functions: &[(&str, bool, usize)]) -> ProofManifest {
        let mut map = BTreeMap::new();
        for (name, verified, checks) in functions {
            map.insert(
                (*name).to_string(),
                FuncProof {
                    verified: *verified,
                    conclusions_checked: *checks,
                    conclusions_passed: if *verified { *checks } else { 0 },
                    used_interval_bounding: false,
                    resource_accesses: Vec::new(),
                },
            );
        }
        ProofManifest {
            schema_version: "1",
            source_hash: format!("sha256:{}", "ab".repeat(32)),
            verified_at: "2026-01-01T00:00:00Z".to_string(),
            functions: map,
            manifest_hash: format!("sha256:{}", "cd".repeat(32)),
        }
    }

    fn guard_for(functions: &[(&str, bool, usize)]) -> Arc<WritGuard<ConservativeDerivation>> {
        Arc::new(WritGuard::from_manifest(
            &manifest_with(functions),
            ConservativeDerivation,
        ))
    }

    #[test]
    fn default_policy_allows_attested_and_denies_unknown() {
        let policy = GuardPolicy::default();
        let guard = guard_for(&[("bump", true, 2)]);

        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "bump", "arguments": {"n": 1}}
        });
        assert_eq!(policy.decide(&guard, &req), Decision::Forward);

        let ghost = serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "delete_everything"}
        });
        match policy.decide(&guard, &ghost) {
            Decision::Deny(msg) => {
                assert!(msg.contains("WRIT DENIED"), "{msg}");
                assert!(msg.contains("no grant exists"), "{msg}");
            }
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn exists_policy_lets_pure_tools_through_the_relay() {
        // The default attempt (Write{"*"}) would deny a Pure-held tool; an
        // explicit Exists override asks only "is this tool attested?".
        let mut policy = GuardPolicy::default();
        policy.set("noop", Attempt::Exists);
        let guard = guard_for(&[("noop", true, 0)]);

        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "noop"}
        });
        assert_eq!(policy.decide(&guard, &req), Decision::Forward);
    }

    #[test]
    fn denial_response_preserves_id_and_marks_is_error() {
        let req = serde_json::json!({"jsonrpc":"2.0","id":42,"method":"tools/call","params":{}});
        let resp = denial_response(&req, "WRIT DENIED: because");
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("because"));
    }

    #[test]
    fn malformed_tool_call_is_denied_not_forwarded() {
        let policy = GuardPolicy::default();
        let guard = guard_for(&[]);
        let bad = serde_json::json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {}
        });
        assert!(matches!(policy.decide(&guard, &bad), Decision::Deny(_)));
        let _ = to_json; // fixture parity with sibling crates
    }
}
