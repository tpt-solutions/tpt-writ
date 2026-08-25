//! The end-to-end demo from the spec's release checklist: a `.telos`
//! service, a guarded example MCP server, and an agent making **one allowed
//! and one denied tool call**.
//!
//! The agent here is deliberately minimal — raw newline-delimited JSON-RPC
//! over the server's stdio, exactly what any MCP client framework speaks.
//!
//! Run: `cargo run -p out-writ-examples --bin agent-demo`

use out_writ_examples::mcp_client::{tool_text, StdioMcpClient};
use serde_json::json;

/// Locate the guarded server binary next to this demo (both are built into
/// the same target dir), falling back to PATH.
fn find_server() -> anyhow::Result<std::path::PathBuf> {
    const NAME: &str = if cfg!(windows) {
        "guarded-counter-server.exe"
    } else {
        "guarded-counter-server"
    };
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap().join(NAME);
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    // Last resort: a workspace-relative dev build.
    let dev = std::path::Path::new("target/debug").join(NAME);
    if dev.exists() {
        return Ok(dev);
    }
    anyhow::bail!(
        "guarded-counter-server not found next to {} or in target/debug — \
         run `cargo build -p out-writ-examples` first",
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    )
}

fn main() -> anyhow::Result<()> {
    let exe = find_server()?;

    println!("agent: spawning guarded MCP server ({})", exe.display());
    let mut client = StdioMcpClient::spawn(exe.to_str().expect("utf-8 path"))?;
    let info = client.initialize()?;
    println!(
        "agent: handshake ok (server: {})",
        info["serverInfo"]["name"].as_str().unwrap_or("<unnamed>")
    );

    // 1) Allowed: proved-Pure tool.
    let resp = client.call_tool("noop", json!({}))?;
    println!("agent: tools/call noop          -> {:?}", tool_text(&resp));

    // 2) Allowed: proved-monotone tool (conservatively Write{"*"}).
    let resp = client.call_tool("bump", json!({"n": 41}))?;
    println!("agent: tools/call bump n=41     -> {:?}", tool_text(&resp));
    let resp = client.call_tool("bump", json!({"n": 1}))?;
    println!("agent: tools/call bump n=1      -> {:?}", tool_text(&resp));

    // 3) Denied: no proof behind this tool, so no grant exists.
    let resp = client.call_tool("delete_everything", json!({}))?;
    println!(
        "agent: tools/call delete_everything -> {:?}",
        tool_text(&resp)
    );

    println!("\nsummary: allowed calls executed; the unproved call was refused");
    Ok(())
}
