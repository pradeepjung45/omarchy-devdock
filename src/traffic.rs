//! Live OS-level network traffic, interface throughput, and process-attributed
//! internet/LAN connection inspector. 100% read-only /proc & /sys, zero root.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::json::Json;
use crate::proc_ports::current_uid;

#[derive(Debug, Clone)]
pub struct NetIfaceStat {
    pub name: String,
    pub kind: &'static str, // "wifi" | "eth" | "docker" | "vpn" | "other"
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errs: u64,
    pub tx_errs: u64,
}

#[derive(Debug, Clone)]
pub struct ActiveConnection {
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub direction: &'static str, // "in" | "out"
    pub scope: &'static str,     // "internet" | "lan" | "tailscale" | "loopback"
    pub service: &'static str,   // "HTTPS" | "HTTP" | "SSH" | ...
    pub state: &'static str,     // "ESTAB" | "SYN"
    pub risk: &'static str,      // "safe" | "cleartext" | "critical"
    pub suspicious_reason: String,
}

#[derive(Debug, Clone)]
pub struct ProcessTrafficGroup {
    pub pid: u32,
    pub comm: String,
    pub exe: String,
    pub owned: bool,
    pub internet_count: usize,
    pub lan_count: usize,
    pub inbound_count: usize,
    pub max_risk: &'static str, // "safe" | "cleartext" | "critical"
    pub connections: Vec<ActiveConnection>,
}

#[derive(Debug, Clone)]
pub struct TrafficState {
    pub timestamp_ms: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub internet_conns: usize,
    pub lan_conns: usize,
    pub inbound_conns: usize,
    pub cleartext_conns: usize,
    pub critical_alerts: Vec<String>,
    pub ifaces: Vec<NetIfaceStat>,
    pub groups: Vec<ProcessTrafficGroup>,
}

struct RawActiveSock {
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    scope: &'static str,
    state: &'static str,
    inode: u64,
}

impl TrafficState {
    pub fn collect(listening_ports: &HashSet<u16>) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ifaces = read_net_dev();
        let (total_rx_bytes, total_tx_bytes) = ifaces
            .iter()
            .filter(|i| matches!(i.kind, "wifi" | "eth" | "vpn"))
            .fold((0u64, 0u64), |(rx, tx), i| {
                (rx.saturating_add(i.rx_bytes), tx.saturating_add(i.tx_bytes))
            });

        let mut socks = Vec::new();
        if let Ok(raw4) = fs::read_to_string("/proc/net/tcp") {
            socks.extend(parse_active_tcp(&raw4, false));
        }
        if let Ok(raw6) = fs::read_to_string("/proc/net/tcp6") {
            socks.extend(parse_active_tcp(&raw6, true));
        }

        // Only correlate non-loopback sockets (or inbound loopback if needed — keep UI focused on real network traffic)
        let net_socks: Vec<RawActiveSock> = socks
            .into_iter()
            .filter(|s| s.scope != "loopback")
            .collect();

        let my_uid = current_uid();
        let wanted_inodes: HashSet<u64> = net_socks.iter().map(|s| s.inode).collect();
        let (inode_to_pid, proc_info) = map_inodes_to_procs(&wanted_inodes, my_uid);

        let mut by_proc: HashMap<(u32, String), ProcessTrafficGroup> = HashMap::new();
        let mut internet_conns = 0usize;
        let mut lan_conns = 0usize;
        let mut inbound_conns = 0usize;
        let mut cleartext_conns = 0usize;
        let mut critical_alerts: Vec<String> = Vec::new();
        let mut seen_crit: HashSet<String> = HashSet::new();

        for sock in net_socks {
            let pid = inode_to_pid.get(&sock.inode).copied().unwrap_or(0);
            let (comm, exe, owned) = proc_info
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| ("system".into(), String::new(), false));

            let direction = if listening_ports.contains(&sock.local_port) {
                "in"
            } else {
                "out"
            };
            let service = classify_port_service(if direction == "in" {
                sock.local_port
            } else {
                sock.remote_port
            });

            let (risk, suspicious_reason) =
                assess_connection_risk(&comm, &exe, sock.scope, sock.remote_port, direction);

            if sock.scope == "internet" {
                internet_conns += 1;
            } else {
                lan_conns += 1;
            }
            if direction == "in" {
                inbound_conns += 1;
            }
            if risk == "cleartext" {
                cleartext_conns += 1;
            }
            if risk == "critical" && !suspicious_reason.is_empty() {
                let alert = format!("{comm} (pid {pid}): {suspicious_reason}");
                if seen_crit.insert(alert.clone()) {
                    critical_alerts.push(alert);
                }
            }

            let conn = ActiveConnection {
                local_port: sock.local_port,
                remote_ip: sock.remote_ip,
                remote_port: sock.remote_port,
                direction,
                scope: sock.scope,
                service,
                state: sock.state,
                risk,
                suspicious_reason,
            };

            let key = (pid, comm.clone());
            let entry = by_proc.entry(key).or_insert_with(|| ProcessTrafficGroup {
                pid,
                comm,
                exe,
                owned,
                internet_count: 0,
                lan_count: 0,
                inbound_count: 0,
                max_risk: "safe",
                connections: Vec::new(),
            });

            if conn.scope == "internet" {
                entry.internet_count += 1;
            } else {
                entry.lan_count += 1;
            }
            if conn.direction == "in" {
                entry.inbound_count += 1;
            }
            if risk_rank(conn.risk) < risk_rank(entry.max_risk) {
                entry.max_risk = conn.risk;
            }
            // Cap per-process detail list to 25 connections to keep JSON crisp
            if entry.connections.len() < 25 {
                entry.connections.push(conn);
            }
        }

        let mut groups: Vec<ProcessTrafficGroup> = by_proc.into_values().collect();
        groups.sort_by(|a, b| {
            risk_rank(a.max_risk)
                .cmp(&risk_rank(b.max_risk))
                .then_with(|| b.internet_count.cmp(&a.internet_count))
                .then_with(|| b.connections.len().cmp(&a.connections.len()))
                .then_with(|| a.comm.cmp(&b.comm))
        });

        Self {
            timestamp_ms,
            total_rx_bytes,
            total_tx_bytes,
            internet_conns,
            lan_conns,
            inbound_conns,
            cleartext_conns,
            critical_alerts,
            ifaces,
            groups,
        }
    }

    pub fn apply_listening_ports(&mut self, listening_ports: &HashSet<u16>) {
        let mut inbound_total = 0usize;
        for g in &mut self.groups {
            let mut g_in = 0usize;
            for c in &mut g.connections {
                if listening_ports.contains(&c.local_port) {
                    c.direction = "in";
                    c.service = classify_port_service(c.local_port);
                    g_in += 1;
                }
            }
            g.inbound_count = g_in;
            inbound_total += g_in;
        }
        self.inbound_conns = inbound_total;
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("timestampMs", Json::Uint(self.timestamp_ms)),
            ("totalRxBytes", Json::Uint(self.total_rx_bytes)),
            ("totalTxBytes", Json::Uint(self.total_tx_bytes)),
            ("internetConns", Json::Uint(self.internet_conns as u64)),
            ("lanConns", Json::Uint(self.lan_conns as u64)),
            ("inboundConns", Json::Uint(self.inbound_conns as u64)),
            ("cleartextConns", Json::Uint(self.cleartext_conns as u64)),
            (
                "criticalAlerts",
                Json::Array(
                    self.critical_alerts
                        .iter()
                        .map(|a| Json::s(a.clone()))
                        .collect(),
                ),
            ),
            (
                "ifaces",
                Json::Array(
                    self.ifaces
                        .iter()
                        .map(|i| {
                            Json::Object(vec![
                                ("name", Json::s(i.name.clone())),
                                ("kind", Json::s(i.kind)),
                                ("rxBytes", Json::Uint(i.rx_bytes)),
                                ("txBytes", Json::Uint(i.tx_bytes)),
                                ("rxErrs", Json::Uint(i.rx_errs)),
                                ("txErrs", Json::Uint(i.tx_errs)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "groups",
                Json::Array(
                    self.groups
                        .iter()
                        .map(|g| {
                            Json::Object(vec![
                                ("pid", Json::Uint(g.pid as u64)),
                                ("comm", Json::s(g.comm.clone())),
                                ("exe", Json::s(g.exe.clone())),
                                ("owned", Json::Bool(g.owned)),
                                ("internetCount", Json::Uint(g.internet_count as u64)),
                                ("lanCount", Json::Uint(g.lan_count as u64)),
                                ("inboundCount", Json::Uint(g.inbound_count as u64)),
                                ("maxRisk", Json::s(g.max_risk)),
                                (
                                    "connections",
                                    Json::Array(
                                        g.connections
                                            .iter()
                                            .map(|c| {
                                                Json::Object(vec![
                                                    ("localPort", Json::Uint(c.local_port as u64)),
                                                    ("remoteIp", Json::s(c.remote_ip.clone())),
                                                    ("remotePort", Json::Uint(c.remote_port as u64)),
                                                    ("direction", Json::s(c.direction)),
                                                    ("scope", Json::s(c.scope)),
                                                    ("service", Json::s(c.service)),
                                                    ("state", Json::s(c.state)),
                                                    ("risk", Json::s(c.risk)),
                                                    ("reason", Json::s(c.suspicious_reason.clone())),
                                                ])
                                            })
                                            .collect(),
                                    ),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

fn risk_rank(r: &str) -> u8 {
    match r {
        "critical" => 0,
        "cleartext" => 1,
        _ => 2,
    }
}

fn read_net_dev() -> Vec<NetIfaceStat> {
    let Ok(raw) = fs::read_to_string("/proc/net/dev") else {
        return Vec::new();
    };
    parse_net_dev(&raw)
}

pub fn parse_net_dev(raw: &str) -> Vec<NetIfaceStat> {
    let mut out = Vec::new();
    for line in raw.lines().skip(2) {
        let Some((name_part, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name_part.trim();
        if name.is_empty() || name == "lo" {
            continue;
        }
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 12 {
            continue;
        }
        let rx_bytes = cols[0].parse::<u64>().unwrap_or(0);
        let rx_errs = cols[2].parse::<u64>().unwrap_or(0) + cols[3].parse::<u64>().unwrap_or(0);
        let tx_bytes = cols[8].parse::<u64>().unwrap_or(0);
        let tx_errs = cols[10].parse::<u64>().unwrap_or(0) + cols[11].parse::<u64>().unwrap_or(0);

        let kind = classify_iface(name);
        out.push(NetIfaceStat {
            name: name.to_string(),
            kind,
            rx_bytes,
            tx_bytes,
            rx_errs,
            tx_errs,
        });
    }
    out.sort_by(|a, b| {
        let rank = |k: &str| match k {
            "wifi" => 0,
            "eth" => 1,
            "vpn" => 2,
            "docker" => 3,
            _ => 4,
        };
        rank(a.kind)
            .cmp(&rank(b.kind))
            .then_with(|| (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes)))
    });
    out
}

fn classify_iface(name: &str) -> &'static str {
    if name.starts_with("wl") || name.starts_with("wlan") {
        "wifi"
    } else if name.starts_with("en") || name.starts_with("eth") {
        "eth"
    } else if name.starts_with("tailscale") || name.starts_with("wg") || name.starts_with("tun") {
        "vpn"
    } else if name.starts_with("docker") || name.starts_with("br-") || name.starts_with("podman") || name.starts_with("veth") {
        "docker"
    } else {
        "other"
    }
}

fn parse_active_tcp(raw: &str, is_v6: bool) -> Vec<RawActiveSock> {
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        // 01 = ESTABLISHED, 02 = SYN_SENT, 03 = SYN_RECV
        let state = match cols[3] {
            "01" => "ESTAB",
            "02" | "03" => "SYN",
            _ => continue,
        };
        let Some((_l_addr, l_port_hex)) = cols[1].split_once(':') else {
            continue;
        };
        let Some((r_addr_hex, r_port_hex)) = cols[2].split_once(':') else {
            continue;
        };
        let Ok(local_port) = u16::from_str_radix(l_port_hex, 16) else {
            continue;
        };
        let Ok(remote_port) = u16::from_str_radix(r_port_hex, 16) else {
            continue;
        };
        let Ok(inode) = cols[9].parse::<u64>() else {
            continue;
        };
        if remote_port == 0 {
            continue;
        }
        let (remote_ip, scope) = decode_remote_addr(r_addr_hex, is_v6);
        out.push(RawActiveSock {
            local_port,
            remote_ip,
            remote_port,
            scope,
            state,
            inode,
        });
    }
    out
}

pub fn decode_remote_addr(hex: &str, is_v6: bool) -> (String, &'static str) {
    if !is_v6 {
        if hex.len() == 8
            && let Ok(v) = u32::from_str_radix(hex, 16)
        {
            let ip = Ipv4Addr::new(
                (v & 0xff) as u8,
                ((v >> 8) & 0xff) as u8,
                ((v >> 16) & 0xff) as u8,
                ((v >> 24) & 0xff) as u8,
            );
            return (ip.to_string(), classify_ipv4_scope(ip));
        }
        return ("0.0.0.0".into(), "loopback");
    }

    if hex.len() == 32 {
        let mut bytes = [0u8; 16];
        let mut ok = true;
        for w in 0..4 {
            let chunk = &hex[w * 8..(w + 1) * 8];
            if let Ok(v) = u32::from_str_radix(chunk, 16) {
                let le = v.to_le_bytes();
                bytes[w * 4..w * 4 + 4].copy_from_slice(&le);
            } else {
                ok = false;
                break;
            }
        }
        if ok {
            let ip6 = Ipv6Addr::from(bytes);
            if let Some(ip4) = ip6.to_ipv4_mapped() {
                return (ip4.to_string(), classify_ipv4_scope(ip4));
            }
            let scope = if ip6.is_loopback() || ip6.is_unspecified() {
                "loopback"
            } else {
                let seg0 = ip6.segments()[0];
                if (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xfe00) == 0xfc00 {
                    "lan"
                } else {
                    "internet"
                }
            };
            return (ip6.to_string(), scope);
        }
    }
    ("::".into(), "loopback")
}

pub fn classify_ipv4_scope(ip: Ipv4Addr) -> &'static str {
    let [a, b, _, _] = ip.octets();
    if a == 127 || ip.is_unspecified() {
        "loopback"
    } else if a == 100 && (64..=127).contains(&b) {
        "tailscale"
    } else if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254) {
        "lan"
    } else {
        "internet"
    }
}

pub fn classify_port_service(port: u16) -> &'static str {
    match port {
        443 | 8443 => "HTTPS",
        80 | 8080 => "HTTP",
        22 => "SSH",
        53 => "DNS",
        853 => "DoT",
        21 => "FTP",
        23 => "Telnet",
        25 | 465 | 587 => "SMTP",
        993 => "IMAPS",
        5432 => "PostgreSQL",
        3306 => "MySQL",
        6379 => "Redis",
        27017 => "MongoDB",
        9092 => "Kafka",
        5222 | 5228 => "Push/XMPP",
        _ => "TCP",
    }
}

pub fn assess_connection_risk(
    comm: &str,
    exe: &str,
    scope: &str,
    remote_port: u16,
    direction: &str,
) -> (&'static str, String) {
    if scope == "internet" {
        if exe.ends_with(" (deleted)") {
            return ("critical", format!("deleted binary talking to internet ({exe})"));
        }
        if exe.starts_with("/tmp/") || exe.starts_with("/dev/shm/") || exe.starts_with("/var/tmp/") {
            return ("critical", format!("binary running from temp path ({exe})"));
        }
        if direction == "out"
            && matches!(remote_port, 21 | 23 | 80 | 3306 | 5432 | 6379 | 27017)
            && !matches!(comm, "pacman" | "curl" | "yay" | "paru")
        {
            return (
                "cleartext",
                format!("unencrypted {} (:{}) over public internet", classify_port_service(remote_port), remote_port),
            );
        }
    }
    ("safe", String::new())
}

fn map_inodes_to_procs(
    wanted: &HashSet<u64>,
    my_uid: u32,
) -> (HashMap<u64, u32>, HashMap<u32, (String, String, bool)>) {
    let mut inode_to_pid = HashMap::new();
    let mut proc_info = HashMap::new();
    if wanted.is_empty() {
        return (inode_to_pid, proc_info);
    }

    let Ok(entries) = fs::read_dir("/proc") else {
        return (inode_to_pid, proc_info);
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(name_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        let pdir = entry.path();
        let Ok(fds) = fs::read_dir(pdir.join("fd")) else {
            continue;
        };
        let mut matched = false;
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path())
                && let Some(tstr) = target.to_str()
                && let Some(rest) = tstr.strip_prefix("socket:[")
                && let Some(num_str) = rest.strip_suffix(']')
                && let Ok(inode) = num_str.parse::<u64>()
                && wanted.contains(&inode)
            {
                inode_to_pid.entry(inode).or_insert(pid);
                matched = true;
            }
        }
        if matched {
            let comm = fs::read_to_string(pdir.join("comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let exe = fs::read_link(pdir.join("exe"))
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_default();
            let uid = fs::read_to_string(pdir.join("status"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find_map(|l| l.strip_prefix("Uid:"))
                        .and_then(|r| r.split_whitespace().next()?.parse::<u32>().ok())
                })
                .unwrap_or(0);
            let protected = matches!(
                comm.as_str(),
                "Hyprland" | "quickshell" | "omarchy-shell" | "systemd" | "devdock" | "dbus-daemon"
            );
            let owned = pid > 1 && uid == my_uid && !protected;
            proc_info.insert(pid, (comm, exe, owned));
        }
    }
    (inode_to_pid, proc_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ipv4_and_mapped_ipv6_scopes() {
        // 1.1.1.1 -> 01010101
        assert_eq!(decode_remote_addr("01010101", false), ("1.1.1.1".into(), "internet"));
        // 192.168.0.1 -> 0100A8C0
        assert_eq!(decode_remote_addr("0100A8C0", false), ("192.168.0.1".into(), "lan"));
        // 100.64.0.5 -> 05004064
        assert_eq!(decode_remote_addr("05004064", false), ("100.64.0.5".into(), "tailscale"));
        // ::ffff:8.8.8.8 -> 0000000000000000FFFF000008080808
        assert_eq!(
            decode_remote_addr("0000000000000000FFFF000008080808", true),
            ("8.8.8.8".into(), "internet")
        );
    }

    #[test]
    fn flags_deleted_and_tmp_internet_binaries_as_critical() {
        let (risk, _) = assess_connection_risk("evil", "/tmp/dropper", "internet", 443, "out");
        assert_eq!(risk, "critical");
        let (risk2, _) = assess_connection_risk("ghost", "/usr/bin/foo (deleted)", "internet", 443, "out");
        assert_eq!(risk2, "critical");
        let (risk3, _) = assess_connection_risk("app", "/usr/bin/app", "internet", 80, "out");
        assert_eq!(risk3, "cleartext");
        let (risk4, _) = assess_connection_risk("chrome", "/usr/bin/chrome", "internet", 443, "out");
        assert_eq!(risk4, "safe");
    }

    #[test]
    fn parses_proc_net_dev_counters() {
        let raw = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0
wlp0s20f3: 1048576 500 1 2 0 0 0 0 524288 300 0 0 0 0 0 0
docker0: 2048 10 0 0 0 0 0 0 1024 8 0 0 0 0 0 0
";
        let ifaces = parse_net_dev(raw);
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].name, "wlp0s20f3");
        assert_eq!(ifaces[0].kind, "wifi");
        assert_eq!(ifaces[0].rx_bytes, 1048576);
        assert_eq!(ifaces[0].rx_errs, 3);
    }
}
