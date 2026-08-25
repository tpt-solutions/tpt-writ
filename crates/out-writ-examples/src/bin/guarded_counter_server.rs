//! A real `rmcp` MCP server whose every tool sits behind a `WritGuard`.
//!
//! This is the Phase 2 proof that the wrapper shape works: the server boots
//! by compiling its own `.telos` service contract (parse → verify → attest,
//! offline via `StaticAgent`), derives one grant per proved function, and
//! then consults the guard at the top of *each tool's dispatch entry* — a
//! thin decorator, not a fork of any server implementation.
//!
//! Tool surface and its provenance:
//!
//! | tool                | `.telos` function      | derived right (v0.1 conservative) |
//! |---------------------|------------------------|-----------------------------------|
//! | `noop`              | `noop`                 | `Pure` (vacuous proof)            |
//! | `bump`              | `bump` (proved monotone increase) | `Write{"*"}` fallback  |
//! | `delete_everything` | — not in any proof —   | no grant; **always denied**       |
//!
//! Denials are returned to the agent as tool output prefixed with
//! `WRIT DENIED:` carrying the enriched held-vs-attempted text.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rmcp::{
    handler::server::wrapper::Parameters, schemars, tool, tool_router, transport::stdio, ServiceExt,
};
use serde::Deserialize;
use tpt_telos_sdk::StaticAgent;
use tpt_writ_core::ConservativeDerivation;
use tpt_writ_mcp::{AccessMode, WritDenied, WritGuard};

/// The service contract this server is accountable to. The same text lives in
/// `examples/counter.telos`; it is inlined so the binary is self-contained.
pub const SERVICE_TELOS: &str = r#"
module CounterService {
    invariant Count { value >= 0 }

    func noop()
    ;

    func bump(c: Count, n: PositiveInt)
        ensures c.value == old(c.value) + n
    ;
}
"#;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BumpArgs {
    /// Non-negative amount to add to the counter.
    pub n: u64,
}

#[derive(Clone)]
pub struct GuardedCounterServer {
    guard: Arc<WritGuard<ConservativeDerivation>>,
    count: Arc<AtomicU64>,
}

impl GuardedCounterServer {
    /// Prove the service contract, derive grants from the attestation, and
    /// build the guard. Fails closed: an unverified contract aborts startup.
    pub fn boot() -> anyhow::Result<Self> {
        let artifact = tpt_telos_sdk::compile(SERVICE_TELOS.trim(), &StaticAgent::new())
            .map_err(|e| anyhow::anyhow!("service contract failed to compile: {e}"))?;
        anyhow::ensure!(
            artifact.all_verified,
            "service contract did not fully verify; refusing to serve unproven tools"
        );

        let guard = WritGuard::from_manifest(&artifact.manifest, ConservativeDerivation);
        eprintln!(
            "writ: guarding {} tools behind proof {}",
            guard.grants().len(),
            hex_short(guard.manifest_hash())
        );
        for (name, grant) in guard.grants() {
            eprintln!("writ:   {name} -> {}", grant.right);
        }

        Ok(Self {
            guard: Arc::new(guard),
            count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The denial path shared by every guarded tool: the enriched
    /// held-vs-attempted text goes back to the calling agent verbatim.
    fn denied(&self, d: &WritDenied) -> String {
        format!("WRIT DENIED: {d}")
    }
}

fn hex_short(bytes: [u8; 32]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[tool_router(server_handler)]
impl GuardedCounterServer {
    /// Pure computation: proved free of resource interaction, so the decorator
    /// only asks "does this tool hold a grant at all?"
    #[tool(description = "No-op that returns ok. Proved Pure by the CounterService contract.")]
    fn noop(&self) -> String {
        match self.guard.check_tool("noop") {
            Ok(()) => "ok".to_string(),
            Err(d) => self.denied(&d),
        }
    }

    /// State mutation: the proof shows a monotone increase, which v0.1's
    /// conservative derivation cannot narrow below Write{"*"} — so the
    /// decorator asks for write access on the counter's resource class.
    #[tool(description = "Add n to the counter. Allowed only while the bump proof holds.")]
    fn bump(&self, Parameters(BumpArgs { n }): Parameters<BumpArgs>) -> String {
        if let Err(d) = self
            .guard
            .check_call("bump", "memory:counter", AccessMode::Write)
        {
            return self.denied(&d);
        }
        let value = self.count.fetch_add(n, Ordering::SeqCst) + n;
        format!("count={value}")
    }

    /// Not covered by any proof — the guard has never heard of this tool.
    #[tool(description = "Destructive op with no proof behind it. Always denied.")]
    fn delete_everything(&self) -> String {
        match self
            .guard
            .check_call("delete_everything", "*", AccessMode::Write)
        {
            Ok(()) => "deleted".to_string(), // unreachable: no grant exists
            Err(d) => self.denied(&d),
        }
    }

    /// Introspection helper so agents can see the enforced capability table.
    #[tool(description = "List the grants currently enforced and their proofs' rights.")]
    fn grants(&self) -> String {
        let mut lines: Vec<String> = self
            .guard
            .grants()
            .iter()
            .map(|(name, g)| {
                let proof_prefix = g
                    .manifest_hash
                    .iter()
                    .take(4)
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                format!("{name}: {} (proof {proof_prefix})", g.right)
            })
            .collect();
        lines.sort();
        lines.join("\n")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = GuardedCounterServer::boot()?;
    let running = server.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}
