//! Full relay round-trip over real OS pipes: a scripted agent talks through
//! `Relay::serve` to a fake guarded MCP server sitting on the other end.
//! Allowed calls reach it; denied calls never do, and their answers come
//! from the relay itself.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::sync::Arc;

use serde_json::{json, Value};
use tpt_telos_codegen::proof::{FuncProof, ProofManifest};
use tpt_writ_cli::relay::{Attempt, GuardPolicy, Relay};
use tpt_writ_core::ConservativeDerivation;
use tpt_writ_mcp::WritGuard;

/// Grants: bump -> Write{"*"} (conservative fallback), noop -> Pure.
fn guard() -> Arc<WritGuard<ConservativeDerivation>> {
    let mut functions = BTreeMap::new();
    for (name, checks) in [("bump", 2usize), ("noop", 0)] {
        functions.insert(
            name.to_string(),
            FuncProof {
                verified: true,
                conclusions_checked: checks,
                conclusions_passed: checks,
                used_interval_bounding: false,
                resource_accesses: Vec::new(),
            },
        );
    }
    let manifest = ProofManifest {
        schema_version: "1",
        source_hash: format!("sha256:{}", "ab".repeat(32)),
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        functions,
        manifest_hash: format!("sha256:{}", "cd".repeat(32)),
    };
    Arc::new(WritGuard::from_manifest(&manifest, ConservativeDerivation))
}

#[test]
fn relay_forwards_allowed_denies_unproved_and_passthrough_the_rest() {
    // Pipes between the relay and the "server":
    //   target stdin : relay writes here, server reads
    //   target stdout: server writes here, relay pumps back
    // std::io::pipe() returns (read_end, write_end).
    let (target_stdin_r, target_stdin_w) = std::io::pipe().expect("stdin pipe");
    let (target_stdout_r, mut target_stdout_w) = std::io::pipe().expect("stdout pipe");

    let server = std::thread::spawn(move || {
        let reader = BufReader::new(target_stdin_r);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let Some(id) = msg.get("id").cloned() else {
                continue;
            };
            let text = match msg["method"].as_str() {
                Some("initialize") => "fake-server-ready".to_string(),
                Some("tools/call") => {
                    format!("echo:{}", msg["params"]["name"].as_str().unwrap_or("?"))
                }
                _ => continue,
            };
            let resp = json!({
                "jsonrpc": "2.0", "id": id,
                "result": {"content": [{"type": "text", "text": text}], "isError": false},
            });
            if writeln!(target_stdout_w, "{resp}").is_err() {
                break;
            }
        }
    });

    let script = "\
{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n\
{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"bump\",\"arguments\":{\"n\":1}}}\n\
{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_everything\"}}\n";

    // Pure-held noop needs an Exists policy entry to pass the default
    // Write-attempt check; included to exercise the override path.
    let mut policy = GuardPolicy::default();
    policy.set("noop", Attempt::Exists);

    let relay = Relay {
        guard: guard(),
        policy,
    };
    let captured = relay
        .serve(
            Cursor::new(script),
            Vec::<u8>::new(),
            target_stdin_w,
            target_stdout_r,
        )
        .expect("serve");

    server.join().expect("server thread");

    let out = String::from_utf8(captured).expect("utf8");
    assert!(
        out.contains("fake-server-ready"),
        "passthrough broken: {out}"
    );
    assert!(
        out.contains("echo:bump"),
        "allowed call must be forwarded: {out}"
    );
    assert!(out.contains("WRIT DENIED"), "denial missing: {out}");
    assert!(
        out.contains("\"isError\":true"),
        "denial must carry isError: {out}"
    );
    assert!(
        !out.contains("echo:delete_everything"),
        "denied call must never reach the server: {out}"
    );
}
