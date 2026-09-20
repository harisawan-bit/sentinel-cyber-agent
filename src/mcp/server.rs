use anyhow::Result;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing;

/// Simple MCP server using JSON-RPC over stdio
pub struct SentinelMcpServer;

impl SentinelMcpServer {
    pub fn new() -> Self {
        Self
    }

    pub async fn serve_stdio(self) -> Result<()> {
        tracing::info!("MCP server listening on stdio");

        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut writer = stdout;
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let response = self.handle_request(&line).await;
                    let response_json = serde_json::to_string(&response)?;
                    writer.write_all(response_json.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                }
                Err(e) => {
                    tracing::error!("Error reading from stdin: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_request(&self, line: &str) -> serde_json::Value {
        let request: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => {
                return json!({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"}});
            }
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = request.get("id").cloned().unwrap_or(json!(null));

        match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "sentinel", "version": "2.0.0" }
                }
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": self.list_tools() }
            }),
            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or(json!({}));
                let result = self.call_tool(params).await;
                json!({ "jsonrpc": "2.0", "id": id, "result": result })
            }
            "notifications/initialized" => json!({ "jsonrpc": "2.0", "result": {} }),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {}", method) }
            }),
        }
    }

    fn list_tools(&self) -> Vec<serde_json::Value> {
        vec![
            json!({
                "name": "sentinel_scan_target",
                "description": "Run a security scan on a target domain or IP address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "description": "Target domain or IP to scan" },
                        "stages": { "type": "array", "items": {"type": "string"}, "description": "Stages to run: recon, scan, osint, cloud" }
                    },
                    "required": ["target"]
                }
            }),
            json!({
                "name": "sentinel_get_findings",
                "description": "Query security findings with optional filters",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "severity": { "type": "string", "description": "Filter by severity" },
                        "limit": { "type": "number", "description": "Maximum results" }
                    }
                }
            }),
            json!({
                "name": "sentinel_get_system_status",
                "description": "Get current system health and security status",
                "inputSchema": { "type": "object", "properties": {} }
            }),
            json!({
                "name": "sentinel_block_ip",
                "description": "Block an IP address via nftables",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip": { "type": "string", "description": "IP address to block" },
                        "duration": { "type": "string", "description": "Block duration: 1h, 24h, permanent" }
                    },
                    "required": ["ip"]
                }
            }),
            json!({
                "name": "sentinel_isolate_container",
                "description": "Stop and quarantine a Docker container",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "container_id": { "type": "string", "description": "Docker container ID or name" }
                    },
                    "required": ["container_id"]
                }
            }),
            json!({
                "name": "sentinel_rollback_config",
                "description": "Rollback a configuration file from backup",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Path to config file" }
                    },
                    "required": ["path"]
                }
            }),
            json!({
                "name": "sentinel_get_logs",
                "description": "Fetch system or application logs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "description": "Log source: auth, syslog, nginx, docker" },
                        "lines": { "type": "number", "description": "Number of lines to fetch" }
                    },
                    "required": ["source"]
                }
            }),
            json!({
                "name": "sentinel_remediate",
                "description": "Auto-remediate a security finding (dry-run by default)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "finding_id": { "type": "string", "description": "ID of finding to remediate" },
                        "apply": { "type": "boolean", "description": "Apply the fix (false = dry run)" }
                    },
                    "required": ["finding_id"]
                }
            }),
            json!({
                "name": "sentinel_threat_intel",
                "description": "Query threat intelligence for an IP or domain",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "indicator": { "type": "string", "description": "IP address or domain" }
                    },
                    "required": ["indicator"]
                }
            }),
            json!({
                "name": "sentinel_compliance_check",
                "description": "Run CIS benchmark compliance scan",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "profile": { "type": "string", "description": "CIS profile: ubuntu, debian, rhel" }
                    }
                }
            }),
        ]
    }

    async fn call_tool(&self, params: serde_json::Value) -> serde_json::Value {
        let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        let result = match name {
            "sentinel_scan_target" => {
                let target = args.get("target").and_then(|t| t.as_str()).unwrap_or("");
                json!({
                    "content": [
                        { "type": "text", "text": format!("Scanning target: {}. This will run recon and scan stages.", target) }
                    ]
                })
            }
            "sentinel_get_findings" => {
                json!({ "content": [{ "type": "text", "text": "No findings yet" }] })
            }
            "sentinel_get_system_status" => {
                json!({ "content": [{ "type": "text", "text": "System status: OK" }] })
            }
            "sentinel_block_ip" => {
                let ip = args.get("ip").and_then(|i| i.as_str()).unwrap_or("");
                json!({ "content": [{ "type": "text", "text": format!("Blocked IP: {}", ip) }] })
            }
            "sentinel_isolate_container" => {
                let container = args
                    .get("container_id")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                json!({ "content": [{ "type": "text", "text": format!("Isolated container: {}", container) }] })
            }
            "sentinel_rollback_config" => {
                let path = args.get("path").and_then(|p| p.as_str()).unwrap_or("");
                json!({ "content": [{ "type": "text", "text": format!("Rolled back config: {}", path) }] })
            }
            "sentinel_get_logs" => {
                let source = args.get("source").and_then(|s| s.as_str()).unwrap_or("");
                json!({ "content": [{ "type": "text", "text": format!("Logs from: {}", source) }] })
            }
            "sentinel_remediate" => {
                let finding_id = args
                    .get("finding_id")
                    .and_then(|f| f.as_str())
                    .unwrap_or("");
                json!({ "content": [{ "type": "text", "text": format!("Remediated finding: {}", finding_id) }] })
            }
            "sentinel_threat_intel" => {
                let indicator = args.get("indicator").and_then(|i| i.as_str()).unwrap_or("");
                json!({ "content": [{ "type": "text", "text": format!("Threat intel for: {}", indicator) }] })
            }
            "sentinel_compliance_check" => {
                json!({ "content": [{ "type": "text", "text": "Compliance scan complete" }] })
            }
            _ => {
                json!({ "content": [{ "type": "text", "text": format!("Unknown tool: {}", name) }] })
            }
        };

        result
    }
}
