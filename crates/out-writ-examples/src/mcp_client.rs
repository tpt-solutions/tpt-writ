//! A minimal MCP client over newline-delimited JSON-RPC on a spawned child's
//! stdio — exactly the wire format an external agent speaks to the guarded
//! server, with none of rmcp's client machinery in between.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

/// Drive one MCP server process over its stdio transport.
pub struct StdioMcpClient {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl StdioMcpClient {
    /// Spawn `exe` with no arguments and connect to it.
    pub fn spawn(exe: &str) -> anyhow::Result<Self> {
        let mut child = Command::new(exe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        Ok(Self {
            reader: BufReader::new(stdout),
            stdin,
            child,
            next_id: 1,
        })
    }

    /// Send a request and wait for the response carrying the same `id`,
    /// skipping any interleaved notifications or unrelated messages.
    pub fn request(&mut self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        writeln!(self.stdin, "{message}")?;
        self.stdin.flush()?;

        let mut line = String::new();
        for _ in 0..10_000 {
            line.clear();
            let n = self.reader.read_line(&mut line)?;
            anyhow::ensure!(n > 0, "server closed the pipe while awaiting `{method}`");
            let msg: Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue, // not JSON — skip
            };
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                return Ok(msg);
            }
            // Anything else (notifications, other ids) is skipped.
        }
        anyhow::bail!("gave up waiting for a response to `{method}`")
    }

    /// Send a notification (no id, no response expected).
    pub fn notify(&mut self, method: &str, params: Value) -> anyhow::Result<()> {
        let message = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        writeln!(self.stdin, "{message}")?;
        Ok(self.stdin.flush()?)
    }

    /// Run the MCP handshake: `initialize` request then the
    /// `notifications/initialized` notification.
    pub fn initialize(&mut self) -> anyhow::Result<Value> {
        let result = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "writ-e2e", "version": "0.1.0"},
            }),
        )?;
        anyhow::ensure!(
            result.get("error").is_none(),
            "initialize failed: {}",
            result["error"]
        );
        self.notify("notifications/initialized", json!({}))?;
        Ok(result["result"].clone())
    }

    /// Call a tool and return the full JSON-RPC response.
    pub fn call_tool(&mut self, name: &str, args: Value) -> anyhow::Result<Value> {
        self.request("tools/call", json!({"name": name, "arguments": args}))
    }

    /// List the server's tools and return the result object.
    pub fn list_tools(&mut self) -> anyhow::Result<Value> {
        let resp = self.request("tools/list", json!({}))?;
        Ok(resp["result"].clone())
    }
}

impl Drop for StdioMcpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Extract the first text block from a successful tool-call result.
pub fn tool_text(response: &Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}
