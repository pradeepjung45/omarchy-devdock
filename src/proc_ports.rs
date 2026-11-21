//! Native Linux `/proc/net/tcp`, `/proc/net/tcp6`, and `/proc/<pid>` scanner.
//! Zero subprocesses needed to list every listening TCP socket, its owner PID,
//! project directory, git branch, framework, RAM usage, uptime, and active tunnels.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;

use crate::detect::{TunnelInfo, classify_process, parse_tunnels_from_argv, resolve_project_and_branch};
use crate::json::Json;

#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub port: u16,
    pub bind_addr: String,
    pub exposed_lan: bool,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub owned: bool,
    pub comm: String,
    pub framework: String,
    pub category: String,
    pub is_http: bool,
    pub project: String,
    pub git_branch: String,
    pub cwd: String,
    pub mem_mb: f64,
    pub uptime_sec: u64,
    pub url: String,
    pub lan_url: String,
    pub container_name: String,
}

impl ListeningPort {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("port", Json::Uint(self.port as u64)),
            ("bindAddr", Json::s(self.bind_addr.clone())),
            ("exposedLan", Json::Bool(self.exposed_lan)),
            ("pid", Json::Uint(self.pid as u64)),
            ("ppid", Json::Uint(self.ppid as u64)),
            ("uid", Json::Uint(self.uid as u64)),
            ("owned", Json::Bool(self.owned)),
            ("comm", Json::s(self.comm.clone())),
            ("framework", Json::s(self.framework.clone())),
            ("category", Json::s(self.category.clone())),
            ("isHttp", Json::Bool(self.is_http)),
            ("project", Json::s(self.project.clone())),
            ("gitBranch", Json::s(self.git_branch.clone())),
            ("cwd", Json::s(self.cwd.clone())),
            ("memMb", Json::Float(self.mem_mb)),
            ("uptimeSec", Json::Uint(self.uptime_sec)),
            ("url", Json::s(self.url.clone())),
            ("lanUrl", Json::s(self.lan_url.clone())),
            ("containerName", Json::s(self.container_name.clone())),
        ])
    }
}

#[derive(Debug, Clone)]
struct RawSocket {
    port: u16,
    bind_addr: String,
    exposed_lan: bool,
    inode: u64,
}

#[derive(Debug, Clone)]
struct ProcMeta {
    ppid: u32,
    uid: u32,
    comm: String,
    cmdline: String,
    cwd: String,
    mem_mb: f64,
    uptime_sec: u64,
}

pub fn current_uid() -> u32 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_uid_from_status(&s))
        .unwrap_or(1000)
}

pub fn scan_ports_and_tunnels(
    lan_ip: &str,
    docker_port_map: &HashMap<u16, String>,
) -> (Vec<ListeningPort>, Vec<TunnelInfo>) {
    let my_uid = current_uid();
    let home = env::var("HOME").unwrap_or_default();
    let sys_uptime = read_system_uptime_sec();
    let clk_tck = 100u64; // Standard USER_HZ on Linux

    let mut sockets = Vec::new();
    if let Ok(raw4) = fs::read_to_string("/proc/net/tcp") {
        sockets.extend(parse_proc_net_tcp(&raw4, false));
    }
    if let Ok(raw6) = fs::read_to_string("/proc/net/tcp6") {
        sockets.extend(parse_proc_net_tcp(&raw6, true));
    }

    let wanted_inodes: HashSet<u64> = sockets.iter().map(|s| s.inode).collect();
    let mut inode_to_pid: HashMap<u64, u32> = HashMap::new();
    let mut proc_cache: HashMap<u32, ProcMeta> = HashMap::new();
    let mut tunnels: Vec<TunnelInfo> = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let Some(name_str) = fname.to_str() else { continue };
            let Ok(pid) = name_str.parse::<u32>() else { continue };

            let pdir = entry.path();
            // Detect SSH / kubectl port-forward tunnels from argv
            let argv = read_argv(&pdir);
            if !argv.is_empty() {
                let first_bin = Path::new(&argv[0])
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&argv[0]);
                if first_bin == "ssh" || first_bin == "kubectl" || first_bin == "k" {
                    let uid = read_proc_uid(&pdir).unwrap_or(0);
                    let found = parse_tunnels_from_argv(pid, &argv, uid == my_uid);
                    tunnels.extend(found);
                }
            }

            // Correlate listening socket inodes to PIDs via /proc/<pid>/fd
            let fd_dir = pdir.join("fd");
            let Ok(fds) = fs::read_dir(fd_dir) else { continue };
            let mut matched = false;
            for fd in fds.flatten() {
                if let Ok(target) = fs::read_link(fd.path())
                    && let Some(tstr) = target.to_str()
                    && let Some(rest) = tstr.strip_prefix("socket:[")
                    && let Some(num_str) = rest.strip_suffix(']')
                    && let Ok(inode) = num_str.parse::<u64>()
                    && wanted_inodes.contains(&inode)
                {
                    inode_to_pid.entry(inode).or_insert(pid);
                    matched = true;
                }
            }
            if matched {
                let meta = read_proc_meta(&pdir, argv, sys_uptime, clk_tck);
                proc_cache.insert(pid, meta);
            }
        }
    }

    // Deduplicate dual-stack sockets bound on the same (port, pid), preferring LAN exposure if either IPv4/IPv6 binds wildcard.
    let mut dedup: HashMap<(u16, u32), ListeningPort> = HashMap::new();
    for sock in sockets {
        let pid = inode_to_pid.get(&sock.inode).copied().unwrap_or(0);
        let meta = proc_cache.get(&pid);

        let (ppid, uid, comm, cmdline, cwd, mem_mb, uptime_sec) = match meta {
            Some(m) => (
                m.ppid,
                m.uid,
                m.comm.clone(),
                m.cmdline.clone(),
                m.cwd.clone(),
                m.mem_mb,
                m.uptime_sec,
            ),
            None => (0, 0, String::from("system"), String::new(), String::new(), 0.0, 0),
        };

        let container_name = docker_port_map.get(&sock.port).cloned().unwrap_or_default();
        let stack = classify_process(&comm, &cmdline, &cwd, sock.port, uid, my_uid);
        let (mut project, git_branch) = resolve_project_and_branch(&cwd, &home);
        if project.is_empty() && !container_name.is_empty() {
            project = container_name.clone();
        }

        let url = if stack.is_http {
            format!("http://localhost:{}", sock.port)
        } else {
            format!("localhost:{}", sock.port)
        };
        let lan_url = if sock.exposed_lan && !lan_ip.is_empty() {
            if stack.is_http {
                format!("http://{}:{}", lan_ip, sock.port)
            } else {
                format!("{}:{}", lan_ip, sock.port)
            }
        } else {
            String::new()
        };

        let entry = ListeningPort {
            port: sock.port,
            bind_addr: sock.bind_addr,
            exposed_lan: sock.exposed_lan,
            pid,
            ppid,
            uid,
            owned: pid > 1 && uid == my_uid,
            comm,
            framework: if !container_name.is_empty() && stack.framework == "Docker" {
                "Docker".into()
            } else {
                stack.framework
            },
            category: if !container_name.is_empty() && stack.category == "system" {
                "data".into()
            } else {
                stack.category.into()
            },
            is_http: stack.is_http,
            project,
            git_branch,
            cwd,
            mem_mb,
            uptime_sec,
            url,
            lan_url,
            container_name,
        };

        let key = (entry.port, entry.pid);
        match dedup.get_mut(&key) {
            Some(existing) => {
                if entry.exposed_lan && !existing.exposed_lan {
                    existing.exposed_lan = true;
                    existing.bind_addr = entry.bind_addr;
                    existing.lan_url = entry.lan_url;
                }
            }
            None => {
                dedup.insert(key, entry);
            }
        }
    }

    let mut ports: Vec<ListeningPort> = dedup.into_values().collect();
    ports.sort_by(|a, b| {
        let rank = |cat: &str| match cat {
            "web" => 0,
            "data" => 1,
            "tunnel" => 2,
            _ => 3,
        };
        rank(&a.category)
            .cmp(&rank(&b.category))
            .then_with(|| a.port.cmp(&b.port))
    });

    tunnels.sort_by_key(|t| t.local_port);
    (ports, tunnels)
}

pub fn tunnel_to_json(t: &TunnelInfo) -> Json {
    Json::Object(vec![
        ("pid", Json::Uint(t.pid as u64)),
        ("kind", Json::s(t.kind)),
        ("direction", Json::s(t.direction.clone())),
        ("localPort", Json::Uint(t.local_port as u64)),
        ("target", Json::s(t.target.clone())),
        ("via", Json::s(t.via.clone())),
        ("owned", Json::Bool(t.owned)),
    ])
}

/// Check whether `pid` currently owns a listening TCP socket on `port` AND matches `my_uid`.
pub fn verify_pid_owns_port(pid: u32, port: u16) -> Result<(), String> {
    if pid <= 1 {
        return Err("refusing to signal init/kernel PID".into());
    }
    let my_uid = current_uid();
    let pdir = Path::new("/proc").join(pid.to_string());
    let uid = read_proc_uid(&pdir).ok_or_else(|| format!("process {pid} not found"))?;
    if uid != my_uid {
        return Err(format!("process {pid} is owned by uid {uid}, not current user {my_uid}"));
    }

    // Verify the process still holds a listening socket on the specified port (or is an active tunnel).
    let (ports, tunnels) = scan_ports_and_tunnels("", &HashMap::new());
    let owns_port = ports.iter().any(|p| p.pid == pid && p.port == port)
        || tunnels.iter().any(|t| t.pid == pid && t.local_port == port);
    if !owns_port {
        return Err(format!("pid {pid} is no longer listening on port {port}"));
    }
    Ok(())
}

/// Walk the parent PID ancestry chain of `pid` (including `pid` itself) up to root.
pub fn pid_ancestry(start_pid: u32) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut cur = start_pid;
    let mut seen = HashSet::new();
    while cur > 1 && seen.insert(cur) && chain.len() < 24 {
        chain.push(cur);
        let stat_path = format!("/proc/{cur}/stat");
        let Ok(raw) = fs::read_to_string(stat_path) else { break };
        let Some((ppid, _)) = parse_ppid_and_starttime(&raw) else { break };
        cur = ppid;
    }
    chain
}

fn parse_proc_net_tcp(raw: &str, is_v6: bool) -> Vec<RawSocket> {
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        // State 0A = TCP_LISTEN
        if cols[3] != "0A" {
            continue;
        }
        let Some((addr_hex, port_hex)) = cols[1].split_once(':') else { continue };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else { continue };
        let Ok(inode) = cols[9].parse::<u64>() else { continue };
        let (bind_addr, exposed_lan) = decode_bind_addr(addr_hex, is_v6);
        out.push(RawSocket {
            port,
            bind_addr,
            exposed_lan,
            inode,
        });
    }
    out
}

fn decode_bind_addr(hex: &str, is_v6: bool) -> (String, bool) {
    if !is_v6 {
        if hex.len() != 8 {
            return ("0.0.0.0".into(), true);
        }
        if let Ok(v) = u32::from_str_radix(hex, 16) {
            let b0 = (v & 0xff) as u8;
            let b1 = ((v >> 8) & 0xff) as u8;
            let b2 = ((v >> 16) & 0xff) as u8;
            let b3 = ((v >> 24) & 0xff) as u8;
            let ip = format!("{b0}.{b1}.{b2}.{b3}");
            let is_docker_bridge = b0 == 172 && (17..=31).contains(&b1) && b2 == 0 && b3 == 1;
            let exposed = b0 != 127 && !(b0 == 169 && b1 == 254) && !is_docker_bridge;
            return (ip, exposed);
        }
        return ("0.0.0.0".into(), true);
    }

    // IPv6 hex (32 chars)
    if hex == "00000000000000000000000000000000" {
        return ("::".into(), true);
    }
    if hex == "00000000000000000000000001000000" {
        return ("::1".into(), false);
    }
    // IPv4-mapped IPv6 ::ffff:127.0.0.1
    if let Some(v4_hex) = hex.strip_prefix("0000000000000000FFFF0000")
        .or_else(|| hex.strip_prefix("0000000000000000ffff0000"))
    {
        return decode_bind_addr(v4_hex, false);
    }
    ("::*".into(), true)
}

fn read_argv(pdir: &Path) -> Vec<String> {
    let Ok(bytes) = fs::read(pdir.join("cmdline")) else { return Vec::new() };
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn read_proc_uid(pdir: &Path) -> Option<u32> {
    let raw = fs::read_to_string(pdir.join("status")).ok()?;
    parse_uid_from_status(&raw)
}

fn parse_uid_from_status(raw: &str) -> Option<u32> {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

fn parse_rss_mb_from_status(raw: &str) -> f64 {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:")
            && let Some(kb) = rest.split_whitespace().next().and_then(|n| n.parse::<u64>().ok())
        {
            return kb as f64 / 1024.0;
        }
    }
    0.0
}

fn read_system_uptime_sec() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

fn parse_ppid_and_starttime(stat: &str) -> Option<(u32, u64)> {
    // Format: `pid (comm with spaces) state ppid ... starttime(field 22)`
    let rparen = stat.rfind(')')?;
    let rest = stat.get(rparen + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0]=state (field 3), fields[1]=ppid (field 4), fields[19]=starttime (field 22)
    let ppid = fields.get(1)?.parse::<u32>().ok()?;
    let start_ticks = fields.get(19)?.parse::<u64>().ok()?;
    Some((ppid, start_ticks))
}

fn read_proc_meta(pdir: &Path, argv: Vec<String>, sys_uptime: u64, clk_tck: u64) -> ProcMeta {
    let comm = fs::read_to_string(pdir.join("comm"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let status = fs::read_to_string(pdir.join("status")).unwrap_or_default();
    let uid = parse_uid_from_status(&status).unwrap_or(0);
    let mem_mb = parse_rss_mb_from_status(&status);
    let stat = fs::read_to_string(pdir.join("stat")).unwrap_or_default();
    let (ppid, start_ticks) = parse_ppid_and_starttime(&stat).unwrap_or((0, 0));
    let uptime_sec = sys_uptime.saturating_sub(start_ticks / clk_tck);
    let cwd = fs::read_link(pdir.join("cwd"))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_default();
    let cmdline = argv.join(" ");

    ProcMeta {
        ppid,
        uid,
        comm,
        cmdline,
        cwd,
        mem_mb,
        uptime_sec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ipv4_and_ipv6_bind_addresses() {
        assert_eq!(decode_bind_addr("0100007F", false), ("127.0.0.1".into(), false));
        assert_eq!(decode_bind_addr("00000000", false), ("0.0.0.0".into(), true));
        assert_eq!(
            decode_bind_addr("00000000000000000000000001000000", true),
            ("::1".into(), false)
        );
        assert_eq!(
            decode_bind_addr("00000000000000000000000000000000", true),
            ("::".into(), true)
        );
    }

    #[test]
    fn parses_proc_net_tcp_listen_rows_only() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 98765
   1: 00000000:1435 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 11111
";
        let rows = parse_proc_net_tcp(sample, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].port, 3000);
        assert_eq!(rows[0].bind_addr, "127.0.0.1");
        assert!(!rows[0].exposed_lan);
        assert_eq!(rows[0].inode, 98765);
    }

    #[test]
    fn parses_stat_with_spaces_in_comm() {
        let sample = "4242 (my node app) S 1234 4242 1234 0 -1 4194304 10 0 0 0 1 1 0 0 20 0 4 0 55000 100 10";
        assert_eq!(parse_ppid_and_starttime(sample), Some((1234, 55000)));
    }
}
