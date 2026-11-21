//! Host DevOps vitals: load average, RAM, disk usage, LAN IP, Tailscale IP.

use std::fs;
use std::net::UdpSocket;
use std::process::Command;

use crate::json::Json;

#[derive(Debug, Clone)]
pub struct HostVitals {
    pub load_1m: f64,
    pub mem_used_gb: f64,
    pub mem_total_gb: f64,
    pub mem_pct: u64,
    pub disk_pct: u64,
    pub lan_ip: String,
    pub tailscale_ip: String,
    pub hostname: String,
}

impl HostVitals {
    pub fn collect() -> Self {
        let load_1m = read_load_1m();
        let (mem_used_gb, mem_total_gb, mem_pct) = read_memory();
        let disk_pct = read_root_disk_pct();
        let lan_ip = detect_lan_ip();
        let tailscale_ip = detect_tailscale_ip();
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();

        Self {
            load_1m,
            mem_used_gb,
            mem_total_gb,
            mem_pct,
            disk_pct,
            lan_ip,
            tailscale_ip,
            hostname,
        }
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("load1m", Json::Float(self.load_1m)),
            ("memUsedGb", Json::Float(self.mem_used_gb)),
            ("memTotalGb", Json::Float(self.mem_total_gb)),
            ("memPct", Json::Uint(self.mem_pct)),
            ("diskPct", Json::Uint(self.disk_pct)),
            ("lanIp", Json::s(self.lan_ip.clone())),
            ("tailscaleIp", Json::s(self.tailscale_ip.clone())),
            ("hostname", Json::s(self.hostname.clone())),
        ])
    }
}

fn read_load_1m() -> f64 {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn read_memory() -> (f64, f64, u64) {
    let raw = match fs::read_to_string("/proc/meminfo") {
        Ok(r) => r,
        Err(_) => return (0.0, 0.0, 0),
    };
    let mut total_kb: u64 = 0;
    let mut avail_kb: u64 = 0;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = parse_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail_kb = parse_kb(rest);
        }
    }
    if total_kb == 0 {
        return (0.0, 0.0, 0);
    }
    let used_kb = total_kb.saturating_sub(avail_kb);
    let total_gb = total_kb as f64 / (1024.0 * 1024.0);
    let used_gb = used_kb as f64 / (1024.0 * 1024.0);
    let pct = ((used_kb as f64 / total_kb as f64) * 100.0).round() as u64;
    (used_gb, total_gb, pct)
}

fn parse_kb(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
}

fn read_root_disk_pct() -> u64 {
    let out = match Command::new("df")
        .args(["--output=pcent", "/"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return 0,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .nth(1)
        .and_then(|line| line.trim().trim_end_matches('%').parse::<u64>().ok())
        .unwrap_or(0)
}

fn detect_lan_ip() -> String {
    // UDP connect selects the kernel's default egress interface without sending
    // any packet over the network.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0")
        && sock.connect("1.1.1.1:80").is_ok()
        && let Ok(addr) = sock.local_addr()
    {
        let ip = addr.ip().to_string();
        if !ip.starts_with("127.") {
            return ip;
        }
    }
    String::new()
}

fn detect_tailscale_ip() -> String {
    // Skip spawning `ip` completely when tailscale0 interface is absent.
    if !std::path::Path::new("/sys/class/net/tailscale0").exists() {
        return String::new();
    }
    // Check tailscale0 / 100.64.0.0/10 address cleanly without network calls.
    let out = match Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", "tailscale0"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return String::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for token in text.split_whitespace() {
        if let Some((ip, _cidr)) = token.split_once('/')
            && ip.starts_with("100.")
        {
            return ip.to_string();
        }
    }
    String::new()
}
