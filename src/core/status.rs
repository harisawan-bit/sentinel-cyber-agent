use anyhow::Result;
use std::process::Command;

pub async fn show() -> Result<()> {
    // Use shell commands for broader compatibility
    let hostname = Command::new("hostname").output()?.stdout;
    let uname = Command::new("uname").arg("-r").output()?.stdout;
    
    println!("System Status:");
    println!("  Hostname: {}", String::from_utf8_lossy(&hostname).trim());
    println!("  Kernel: {}", String::from_utf8_lossy(&uname).trim());
    
    // Use sysinfo for dynamic metrics
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();
    
    if let Some(cpu) = sys.cpus().first() {
        println!("  CPU: {:.1}%", cpu.cpu_usage());
    }
    println!("  RAM: {:.1}% used / {:.1} GB total", 
        (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0,
        sys.total_memory() as f64 / 1_073_741_824.0
    );
    
    Ok(())
}
