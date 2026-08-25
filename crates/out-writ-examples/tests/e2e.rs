//! End-to-end test: the *real* guarded `rmcp` server binary, driven over its
//! actual stdio transport with newline-delimited JSON-RPC — no mocks. An
//! allowed call passes through to the real handler; a disallowed call comes
//! back denied with the enriched held-vs-attempted text.

use out_writ_examples::mcp_client::{tool_text, StdioMcpClient};
use serde_json::json;

fn spawn_server() -> StdioMcpClient {
    let exe = env!("CARGO_BIN_EXE_guarded-counter-server");
    let mut client = StdioMcpClient::spawn(exe).expect("spawn guarded-counter-server");
    client.initialize().expect("initialize handshake");
    client
}

#[test]
fn allowed_calls_pass_and_unproved_call_is_denied() {
    let mut client = spawn_server();

    // The server exposes its full tool surface, guarded or not...
    let tools = client.list_tools().expect("tools/list");
    let names: Vec<String> = tools["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    for expected in ["noop", "bump", "delete_everything", "grants"] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing tool `{expected}` in {names:?}"
        );
    }

    // ...and the guard sits at dispatch:
    // 1) proved-Pure tool: passes.
    let out = client.call_tool("noop", json!({})).expect("call noop");
    assert_eq!(tool_text(&out), "ok", "raw response: {out}");

    // 2) proved-monotone tool (conservatively Write{"*"}): passes, twice,
    //    and the real handler state advances.
    let out = client
        .call_tool("bump", json!({"n": 5}))
        .expect("call bump");
    assert_eq!(tool_text(&out), "count=5", "raw response: {out}");
    let out = client
        .call_tool("bump", json!({"n": 2}))
        .expect("call bump");
    assert_eq!(tool_text(&out), "count=7", "state must persist: {out}");

    // 3) unproved tool: denied with held-vs-attempted clarity.
    let out = client
        .call_tool("delete_everything", json!({}))
        .expect("call delete_everything");
    let text = tool_text(&out);
    assert!(text.starts_with("WRIT DENIED:"), "denial text: {text}");
    assert!(
        text.contains("no grant exists"),
        "must explain that nothing was held: {text}"
    );

    // 4) introspection shows the enforced table.
    let out = client.call_tool("grants", json!({})).expect("grants");
    let table = tool_text(&out);
    assert!(table.contains("noop: Pure"), "grant table: {table}");
    assert!(table.contains("bump: Write(*)"), "grant table: {table}");
}
