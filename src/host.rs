//! Host DevOps vitals: load average, RAM, disk usage, LAN IP, Tailscale IP.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;

use crate::json::Json;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThemePalette {
    pub red: String,
    pub green: String,
    pub amber: String,
    pub blue: String,
    pub purple: String,
    pub cyan: String,
}

impl ThemePalette {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("red", Json::s(self.red.clone())),
            ("green", Json::s(self.green.clone())),
            ("amber", Json::s(self.amber.clone())),
            ("blue", Json::s(self.blue.clone())),
            ("purple", Json::s(self.purple.clone())),
            ("cyan", Json::s(self.cyan.clone())),
        ])
    }
}

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
    pub palette: ThemePalette,
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
        let palette = read_omarchy_theme_palette();

        Self {
            load_1m,
            mem_used_gb,
            mem_total_gb,
            mem_pct,
            disk_pct,
            lan_ip,
            tailscale_ip,
            hostname,
            palette,
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
            ("palette", self.palette.to_json()),
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

fn read_omarchy_theme_palette() -> ThemePalette {
    let home = match env::var("HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h),
        _ => return ThemePalette::default(),
    };
    let candidates = [
        home.join(".local/state/omarchy/current/theme/colors.toml"),
        home.join(".config/omarchy/current/theme/colors.toml"),
    ];
    for path in candidates {
        if let Ok(raw) = fs::read_to_string(path) {
            return parse_omarchy_theme_palette(&raw);
        }
    }
    ThemePalette::default()
}

pub fn parse_omarchy_theme_palette(raw: &str) -> ThemePalette {
    let mut map: HashMap<String, String> = HashMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches(|c| c == '"' || c == '\'');
        if is_valid_hex6(val) {
            map.insert(key.to_string(), val.to_ascii_lowercase());
        }
    }

    let pick = |keys: &[&str], pred: fn(f64, f64) -> bool, fallback: &str| -> String {
        for &k in keys {
            if let Some(hex) = map.get(k)
                && let Some((h, s)) = hex_hue_sat(hex)
                && s >= 0.18
                && pred(h, s)
            {
                return hex.clone();
            }
        }
        fallback.to_string()
    };

    let red = pick(&["color1", "color9"], |h, _| !(25.0..325.0).contains(&h), "");
    let green = pick(&["color2", "color10"], |h, _| (85.0..=185.0).contains(&h), "#4ade80");
    let amber = pick(&["color3", "color11"], |h, _| (22.0..=75.0).contains(&h), "#f5b971");
    let blue = pick(&["color4", "color12"], |h, _| (190.0..=258.0).contains(&h), "#60a5fa");
    let purple = pick(&["color5", "color13"], |h, _| (255.0..=325.0).contains(&h), "#c084fc");
    let cyan = pick(
        &["color6", "color14", "color3", "color10"],
        |h, _| (165.0..=212.0).contains(&h),
        "#38bdf8",
    );

    ThemePalette {
        red,
        green,
        amber,
        blue,
        purple,
        cyan,
    }
}

fn is_valid_hex6(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(|b| b.is_ascii_hexdigit())
}

fn hex_hue_sat(hex: &str) -> Option<(f64, f64)> {
    if !is_valid_hex6(hex) {
        return None;
    }
    let r = u8::from_str_radix(&hex[1..3], 16).ok()? as f64 / 255.0;
    let g = u8::from_str_radix(&hex[3..5], 16).ok()? as f64 / 255.0;
    let b = u8::from_str_radix(&hex[5..7], 16).ok()? as f64 / 255.0;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let delta = max - min;
    if delta < 1e-6 {
        return Some((0.0, 0.0));
    }
    let sat = delta / max;
    let mut hue = if (max - r).abs() < 1e-6 {
        60.0 * (((g - b) / delta) % 6.0)
    } else if (max - g).abs() < 1e-6 {
        60.0 * (((b - r) / delta) + 2.0)
    } else {
        60.0 * (((r - g) / delta) + 4.0)
    };
    if hue < 0.0 {
        hue += 360.0;
    }
    Some((hue, sat))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tokyo_night_palette_verbatim() {
        let toml = r##"
color1 = "#f7768e"
color2 = "#9ece6a"
color3 = "#e0af68"
color4 = "#7aa2f7"
color5 = "#bb9af7"
color6 = "#7dcfff"
"##;
        let pal = parse_omarchy_theme_palette(toml);
        assert_eq!(pal.red, "#f7768e");
        assert_eq!(pal.green, "#9ece6a");
        assert_eq!(pal.amber, "#e0af68");
        assert_eq!(pal.blue, "#7aa2f7");
        assert_eq!(pal.purple, "#bb9af7");
        assert_eq!(pal.cyan, "#7dcfff");
    }

    #[test]
    fn guards_warning_amber_when_theme_color3_is_cyan() {
        let toml = r##"
color1 = "#ff7b92"
color2 = "#4ecdc4"
color3 = "#82eeff"
color4 = "#6a85ff"
color5 = "#b388eb"
color6 = "#c9aff0"
color14 = "#a5f5ff"
"##;
        let pal = parse_omarchy_theme_palette(toml);
        assert_eq!(pal.red, "#ff7b92");
        assert_eq!(pal.green, "#4ecdc4");
        assert_eq!(pal.amber, "#f5b971");
        assert_eq!(pal.blue, "#6a85ff");
        assert_eq!(pal.purple, "#b388eb");
        assert_eq!(pal.cyan, "#a5f5ff");
    }
}
