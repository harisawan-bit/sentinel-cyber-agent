pub mod server;

use anyhow::Result;
use tracing;

pub async fn start_dashboard(config_path: &str) -> Result<()> {
    server::start_dashboard(config_path).await
}
