use clap::Parser;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// A safe, low-level, and incredibly fast TCP port scanner.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target IP address or hostname to scan
    #[arg(short, long)]
    target: String,

    /// Starting port for the scan range
    #[arg(short, long, default_value_t = 1)]
    start_port: u16,

    /// Ending port for the scan range
    #[arg(short, long, default_value_t = 1024)]
    end_port: u16,

    /// Maximum number of concurrent workers (threads/tasks)
    #[arg(short, long, default_value_t = 1000)]
    workers: usize,

    /// Connection timeout in milliseconds
    #[arg(short = 't', long, default_value_t = 1000)]
    timeout_ms: u64,
}

impl Args {
    /// Resolves the hostname or parses the IP address.
    fn resolve_target(&self) -> Result<IpAddr, String> {
        let addr_str = format!("{}:0", self.target);
        match addr_str.to_socket_addrs() {
            Ok(mut iter) => {
                if let Some(socket_addr) = iter.next() {
                    Ok(socket_addr.ip())
                } else {
                    Err(format!("Could not resolve target: {}", self.target))
                }
            }
            Err(e) => Err(format!("Error resolving target {}: {}", self.target, e)),
        }
    }
}

async fn scan_port(ip: IpAddr, port: u16, timeout_duration: Duration) {
    let socket_addr = SocketAddr::new(ip, port);
    
    // Connect with a timeout (Version 1.0 core & Version 3.0 timeout)
    if let Ok(Ok(mut stream)) = timeout(timeout_duration, TcpStream::connect(&socket_addr)).await {
        println!("[+] Port {} is OPEN", port);
        
        // Version 4.0: Basic TCP Service Banner Grabbing
        let mut buffer = [0; 512];
        let mut banner_grabbed = false;
        
        // Some services send a banner immediately upon connection (e.g., SSH, FTP)
        // Wait briefly for unsolicited data
        if let Ok(Ok(bytes_read)) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            if bytes_read > 0 {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                let clean_banner = banner.lines().next().unwrap_or("").trim();
                if !clean_banner.is_empty() {
                    println!("    -> Banner: {}", clean_banner);
                    banner_grabbed = true;
                }
            }
        }

        // If no banner was sent proactively, try sending a generic HTTP probe
        if !banner_grabbed {
            let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
            if let Ok(Ok(bytes_read)) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
                if bytes_read > 0 {
                    let banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                    let clean_banner = banner.lines().next().unwrap_or("").trim();
                    if !clean_banner.is_empty() {
                        println!("    -> Banner: {}", clean_banner);
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let target_ip = match args.resolve_target() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    println!("Starting scan on target: {} ({})", args.target, target_ip);
    println!("Ports: {} to {}", args.start_port, args.end_port);
    println!("Workers: {}", args.workers);
    println!("Timeout: {} ms", args.timeout_ms);
    println!("============================================================");

    let timeout_duration = Duration::from_millis(args.timeout_ms);
    // Version 2.0: High concurrency with tokio and a semaphore to limit workers
    let semaphore = Arc::new(Semaphore::new(args.workers));
    let mut tasks = Vec::new();

    for port in args.start_port..=args.end_port {
        let sem_clone = Arc::clone(&semaphore);
        let ip_clone = target_ip;

        let task = tokio::spawn(async move {
            // Acquire a permit. If workers limit is reached, this will wait.
            let _permit = sem_clone.acquire().await.unwrap();
            scan_port(ip_clone, port, timeout_duration).await;
        });

        tasks.push(task);
    }

    // Await all spawned tasks
    for task in tasks {
        let _ = task.await;
    }

    println!("============================================================");
    println!("Scan Complete.");
}
