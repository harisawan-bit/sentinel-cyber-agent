use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub tool: String,
    pub finding_type: String,
    pub value: String,
    pub target: String,
    pub severity: String,
    pub detail: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target: String,
    pub stages: Option<Vec<String>>,
    pub timeout_seconds: u64,
    pub max_concurrent: usize,
}

/// Run the orchestrator pipeline against a target
pub async fn scan(target: &str, stages: Option<Vec<String>>) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let stage_filter = stages.unwrap_or_else(|| vec!["recon".to_string(), "scan".to_string()]);

    // Run recon plugins
    if stage_filter.contains(&"recon".to_string()) {
        findings.extend(crate::plugins::run_recon(target).await?);
    }

    // Run scan plugins
    if stage_filter.contains(&"scan".to_string()) {
        findings.extend(crate::plugins::run_scan(target).await?);
    }

    // Run osint plugins
    if stage_filter.contains(&"osint".to_string()) {
        findings.extend(crate::plugins::run_osint(target).await?);
    }

    // Run cloud plugins
    if stage_filter.contains(&"cloud".to_string()) {
        findings.extend(crate::plugins::run_cloud(target).await?);
    }

    Ok(findings)
}
