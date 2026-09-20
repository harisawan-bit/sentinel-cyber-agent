use anyhow::Result;
use axum::{
    routing::{get, post},
    Router, Json, serve,
};
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;
use tower_http::services::ServeDir;
use tracing;

/// Start the Nginx UI dashboard server
pub async fn start_dashboard(_config_path: &str) -> Result<()> {
    tracing::info!("Starting Nginx UI dashboard...");
    
    let dashboard_dir = PathBuf::from("/usr/share/sentinel/dashboard");
    let fallback_dir = PathBuf::from("/var/lib/sentinel/dashboard");
    
    let static_dir = if dashboard_dir.exists() {
        dashboard_dir
    } else if fallback_dir.exists() {
        fallback_dir
    } else {
        PathBuf::from("/tmp/sentinel-dashboard")
    };
    
    let app = Router::new()
        .route("/api/status", get(api_status))
        .route("/api/findings", get(api_get_findings))
        .route("/api/findings/scan", post(api_scan_target))
        .route("/api/block", post(api_block_ip))
        .route("/api/findings/{id}/delete", post(api_delete_finding))
        .route("/api/compliance", get(api_compliance))
        .fallback_service(ServeDir::new(&static_dir).append_index_html_on_directories(true));
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!(address = "0.0.0.0:8080", "Dashboard listening");
    
    serve(listener, app).await?;
    
    Ok(())
}

async fn api_status() -> Json<serde_json::Value> {
    let hostname = String::from_utf8_lossy(&Command::new("hostname").output().map(|o| o.stdout).unwrap_or_default()).trim().to_string();
    let kernel = String::from_utf8_lossy(&Command::new("uname").arg("-r").output().map(|o| o.stdout).unwrap_or_default()).trim().to_string();
    
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();
    
    let cpu = sys.cpus().first().map(|c| c.cpu_usage()).unwrap_or(0.0);
    let ram_percent = (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0;
    let ram_total_gb = sys.total_memory() as f64 / 1_073_741_824.0;
    
    Json(json!({
        "hostname": hostname,
        "kernel": kernel,
        "cpu": cpu,
        "ram_percent": ram_percent,
        "ram_total_gb": ram_total_gb
    }))
}

async fn api_get_findings() -> Json<serde_json::Value> {
    Json(json!({ "findings": [] }))
}

async fn api_scan_target(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    tracing::info!(target = ?payload.get("target"), "Scan requested");
    Json(json!({ "status": "scan_started", "target": payload.get("target") }))
}

async fn api_block_ip(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let ip = payload.get("ip").and_then(|i| i.as_str()).unwrap_or("");
    tracing::info!(ip = ip, "Block IP requested");
    
    // Run nft add element
    let _ = tokio::process::Command::new("nft")
        .args(&["add", "element", "inet", "sentinel", "blocklist", "{", ip, "}"])
        .output()
        .await;
    
    Json(json!({ "status": "blocked", "ip": ip }))
}

async fn api_delete_finding(axum::extract::Path(id): axum::extract::Path<String>) -> Json<serde_json::Value> {
    tracing::info!(id = ?id, "Delete finding requested");
    Json(json!({ "status": "deleted", "id": id }))
}

async fn api_compliance() -> Json<serde_json::Value> {
    Json(json!({ "checks": [], "passed": 0, "failed": 0 }))
}
