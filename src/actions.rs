//! Strictly validated actions: safe stop/kill, Hyprland terminal focus,
//! browser URL open, Docker/Podman lifecycle, kube context switching, and log viewing.
//! Never uses shell string interpolation (`sh -c`).

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::docker::{ContainersState, detect_engine};
use crate::json::Json;
use crate::kube::KubeState;
use crate::proc_ports::{current_uid, pid_ancestry, verify_pid_owns_port};

/// Send SIGTERM (force=false) or SIGKILL (force=true) to a process strictly
/// verified to belong to the current user and actively listening on `port`.
pub fn signal_port_pid(pid: u32, port: u16, force: bool) -> Result<String, String> {
    verify_pid_owns_port(pid, port)?;
    let sig_flag = if force { "-KILL" } else { "-TERM" };
    let status = Command::new("kill")
        .args([sig_flag, &pid.to_string()])
        .status()
        .map_err(|e| format!("kill failed: {e}"))?;
    if status.success() {
        Ok(if force { "killed" } else { "stopped" }.into())
    } else {
        Err(format!("kill returned exit code {:?}", status.code()))
    }
}

/// Strictly validate an HTTP(S) local/LAN URL before handing it to `xdg-open`.
pub fn validate_local_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| "URL must start with http:// or https://".to_string())?;
    let (host, port_str) = rest
        .split_once(':')
        .ok_or_else(|| "URL must include an explicit :port".to_string())?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| "invalid port number".to_string())?;
    if port == 0 {
        return Err("port must be > 0".into());
    }
    let valid_host = host == "localhost"
        || host
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
            && host.split('.').count() == 4;
    if !valid_host {
        return Err(format!("refusing to open non-local/IP host: {host}"));
    }
    Ok(())
}

pub fn open_url(url: &str) -> Result<String, String> {
    validate_local_url(url)?;
    Command::new("xdg-open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("xdg-open failed: {e}"))?;
    Ok("opened".into())
}

/// Copy safe text to Wayland clipboard via `wl-copy`.
pub fn copy_text(text: &str) -> Result<String, String> {
    if text.len() > 2048 || text.contains('\0') {
        return Err("clipboard text invalid or too long".into());
    }
    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("wl-copy failed: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(text.as_bytes());
    }
    Ok("copied".into())
}

/// Jump Hyprland focus to the terminal/editor window whose PID is an ancestor of `pid`.
pub fn focus_hyprland_window(pid: u32) -> Result<String, String> {
    if pid <= 1 {
        return Err("invalid pid".into());
    }
    let chain = pid_ancestry(pid);
    if chain.is_empty() {
        return Err(format!("process {pid} not found"));
    }

    let clients_json = hypr_socket_cmd("j/clients")
        .or_else(|_| {
            Command::new("hyprctl")
                .args(["clients", "-j"])
                .output()
                .map_err(|e| e.to_string())
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })?;

    let matched_addr = find_matching_hypr_address(&clients_json, &chain)
        .ok_or_else(|| "no Hyprland window owns this process (background daemon)".to_string())?;

    let dispatch = format!("dispatch focuswindow address:{matched_addr}");
    hypr_socket_cmd(&dispatch)?;
    Ok(matched_addr)
}

fn hypr_socket_cmd(cmd: &str) -> Result<String, String> {
    let sig = env::var("HYPRLAND_INSTANCE_SIGNATURE").map_err(|_| "no Hyprland session")?;
    let runtime = env::var("XDG_RUNTIME_DIR").map_err(|_| "no XDG_RUNTIME_DIR")?;
    let sock_path = format!("{runtime}/hypr/{sig}/.socket.sock");
    let mut stream = UnixStream::connect(&sock_path).map_err(|e| format!("hypr socket: {e}"))?;
    stream
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("hypr write: {e}"))?;
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    Ok(resp)
}

/// Lightweight parser for Hyprland `j/clients` JSON objects matching `"address"` + `"pid"`.
pub fn find_matching_hypr_address(clients_json: &str, ancestry: &[u32]) -> Option<String> {
    let mut current_addr: Option<String> = None;
    let mut pairs: Vec<(u32, String)> = Vec::new();

    for line in clients_json.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"address\":") {
            let val = rest.trim().trim_end_matches(',').trim().trim_matches('"');
            if val.starts_with("0x") {
                current_addr = Some(val.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("\"pid\":") {
            let num_str = rest.trim().trim_end_matches(',').trim();
            if let Ok(p) = num_str.parse::<u32>()
                && let Some(addr) = current_addr.take()
            {
                pairs.push((p, addr));
            }
        }
    }

    // Prefer closest ancestor first (child -> shell -> terminal)
    for anc in ancestry {
        if let Some((_, addr)) = pairs.iter().find(|(p, _)| p == anc) {
            return Some(addr.clone());
        }
    }
    None
}

pub fn validate_identifier(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 128 {
        return Err("invalid identifier length".into());
    }
    if s.starts_with('-') {
        return Err("identifier must not start with '-'".into());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':'))
    {
        return Err("identifier contains disallowed characters".into());
    }
    Ok(())
}

pub fn container_action(action: &str, id: &str) -> Result<String, String> {
    if !matches!(action, "start" | "stop" | "restart" | "logs" | "exec") {
        return Err(format!("unsupported container action: {action}"));
    }
    validate_identifier(id)?;
    let engine = detect_engine().ok_or_else(|| "no container engine running".to_string())?;

    if action == "logs" {
        return spawn_terminal_cmd(&[engine, "logs", "-f", "--tail", "150", id], true, "DevDock Logs");
    }
    if action == "exec" {
        return spawn_terminal_cmd(&[engine, "exec", "-it", id, "sh"], false, "DevDock Shell");
    }

    // Fast path: direct UNIX socket HTTP/1.1 call (no Go CLI startup lag)
    if let Ok(msg) = crate::docker_sock::lifecycle(action, id) {
        return Ok(msg);
    }

    let status = Command::new(engine)
        .args([action, id])
        .status()
        .map_err(|e| format!("{engine} {action} failed: {e}"))?;
    if status.success() {
        Ok(format!("{action}ed"))
    } else {
        Err(format!("{engine} {action} failed with {:?}", status.code()))
    }
}

/// Start or stop every container belonging to a Docker Compose project concurrently.
pub fn compose_stack_action(action: &str, project: &str) -> Result<String, String> {
    if !matches!(action, "start" | "stop") {
        return Err(format!("unsupported stack action: {action}"));
    }
    validate_identifier(project)?;
    let state = ContainersState::collect();
    if !state.available {
        return Err("no container engine running".into());
    }
    let targets: Vec<String> = state
        .items
        .into_iter()
        .filter(|c| c.compose_project == project)
        .filter(|c| {
            if action == "start" {
                c.state != "running"
            } else {
                c.state == "running"
            }
        })
        .map(|c| c.id)
        .collect();

    if targets.is_empty() {
        return Ok(format!("stack {project} already {action}ed"));
    }

    let count = targets.len();
    let mut errors = Vec::new();
    thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|id| s.spawn(move || container_action(action, id)))
            .collect();
        for h in handles {
            if let Ok(Err(e)) = h.join() {
                errors.push(e);
            }
        }
    });

    if errors.is_empty() {
        Ok(format!("{action}ed {count} container(s) in {project}"))
    } else {
        Err(errors.join("; "))
    }
}

/// Pure-Rust local HTTP HEAD / TCP latency probe (zero curl, < 2ms typical).
pub fn probe_port(port: u16) -> Result<String, String> {
    if port == 0 {
        return Err("port must be > 0".into());
    }
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|_| "invalid localhost addr".to_string())?;
    let start = Instant::now();
    let stream_res = TcpStream::connect_timeout(&addr, Duration::from_millis(1200));
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let Ok(mut stream) = stream_res else {
        return Ok(Json::Object(vec![
            ("port", Json::Uint(port as u64)),
            ("ok", Json::Bool(false)),
            ("status", Json::s("refused")),
            ("ms", Json::Float(elapsed_ms)),
        ])
        .to_string_compact());
    };

    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));
    let req = format!("HEAD / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(req.as_bytes());

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;

    let status_label = parse_http_status_line(&buf[..n]).unwrap_or_else(|| "TCP open".into());
    let ok = !status_label.starts_with('5');

    Ok(Json::Object(vec![
        ("port", Json::Uint(port as u64)),
        ("ok", Json::Bool(ok)),
        ("status", Json::s(status_label)),
        ("ms", Json::Float(total_ms)),
    ])
    .to_string_compact())
}

pub fn parse_http_status_line(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let line = text.lines().next()?.trim();
    if !line.starts_with("HTTP/") {
        return None;
    }
    let rest = line.split_once(' ')?.1.trim();
    if rest.is_empty() {
        return None;
    }
    Some(rest.chars().take(24).collect())
}

/// Strictly UID-verified signal for a non-system process (used from the Net tab).
pub fn signal_owned_pid(pid: u32, force: bool) -> Result<String, String> {
    if pid <= 1 {
        return Err("refusing to signal system pid".into());
    }
    let status_txt = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| format!("process {pid} not found"))?;
    let proc_uid = status_txt
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().next()?.parse::<u32>().ok())
        .ok_or_else(|| "cannot verify process owner".to_string())?;
    if proc_uid != current_uid() {
        return Err("refusing to signal process owned by another user".into());
    }
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string();
    if matches!(
        comm.as_str(),
        "Hyprland" | "quickshell" | "omarchy-shell" | "systemd" | "devdock" | "dbus-daemon"
    ) {
        return Err(format!("refusing to signal protected desktop process ({comm})"));
    }
    let sig_flag = if force { "-KILL" } else { "-TERM" };
    let status = Command::new("kill")
        .args([sig_flag, &pid.to_string()])
        .status()
        .map_err(|e| format!("kill failed: {e}"))?;
    if status.success() {
        Ok(format!(
            "{} {comm} (pid {pid})",
            if force { "killed" } else { "stopped" }
        ))
    } else {
        Err(format!("kill returned exit code {:?}", status.code()))
    }
}

/// Emit a crash-watchdog desktop notification via `notify-send` (pure argv).
pub fn notify_watchdog(title: &str, body: &str) -> Result<String, String> {
    let t: String = title.chars().filter(|c| !c.is_control()).take(80).collect();
    let b: String = body.chars().filter(|c| !c.is_control()).take(220).collect();
    if t.is_empty() || b.is_empty() {
        return Err("notification title and body required".into());
    }
    if !command_exists("notify-send") {
        return Ok("skipped".into());
    }
    let _ = Command::new("notify-send")
        .args(["-a", "DevDock", "-u", "normal", "--", &t, &b])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    Ok("notified".into())
}

pub fn container_tail_logs(id: &str, tail: u32) -> Result<String, String> {
    validate_identifier(id)?;
    if let Ok(text) = crate::docker_sock::tail_logs(id, tail) {
        return Ok(text);
    }
    let engine = detect_engine().ok_or_else(|| "no container engine running".to_string())?;
    let tail_str = tail.clamp(10, 500).to_string();
    let out = Command::new(engine)
        .args(["logs", "--tail", &tail_str, id])
        .output()
        .map_err(|e| format!("{engine} logs failed: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.stderr.is_empty() {
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Ok(crate::docker_sock::strip_ansi(&combined))
}

pub fn switch_kube_context(context: &str) -> Result<String, String> {
    validate_identifier(context)?;
    let kube = KubeState::collect();
    if !kube.contexts.iter().any(|c| c.name == context) {
        return Err(format!("context '{context}' not found in kubeconfig"));
    }
    let status = Command::new("kubectl")
        .args(["config", "use-context", context])
        .status()
        .map_err(|e| format!("kubectl failed: {e}"))?;
    if status.success() {
        Ok(context.to_string())
    } else {
        Err(format!("kubectl exited with {:?}", status.code()))
    }
}

pub fn view_service_logs(unit: &str, user_scope: bool) -> Result<String, String> {
    validate_identifier(unit)?;
    if user_scope {
        spawn_terminal_cmd(&["journalctl", "--user", "-u", unit, "-n", "120", "-f"], true, "DevDock Logs")
    } else {
        spawn_terminal_cmd(&["journalctl", "-u", unit, "-n", "120", "-f"], true, "DevDock Logs")
    }
}

/// On-demand reverse DNS lookup for a validated IP address (never called during background scans).
pub fn reverse_dns(ip: &str) -> Result<String, String> {
    let trimmed = ip.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || trimmed.starts_with('-')
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
    {
        return Err("invalid IP address".into());
    }
    let out = Command::new("getent")
        .args(["hosts", trimmed])
        .output()
        .map_err(|e| format!("getent failed: {e}"))?;
    let line = String::from_utf8_lossy(&out.stdout);
    if let Some(host) = line.split_whitespace().nth(1) {
        Ok(host.to_string())
    } else {
        Ok(format!("{trimmed} (no PTR record)"))
    }
}

fn spawn_terminal_cmd(cmd: &[&str], hold_on_exit: bool, title: &str) -> Result<String, String> {
    // Detach via `setsid` (so Quickshell Process teardown never kills the terminal)
    // and pass hold flags when viewing logs so exited container/service logs stay visible.
    let candidates: &[(&str, Vec<&str>)] = &[
        (
            "foot",
            if hold_on_exit {
                vec!["-H", "-T", title]
            } else {
                vec!["-T", title]
            },
        ),
        (
            "ghostty",
            if hold_on_exit {
                vec!["--wait-after-command=true", "-e"]
            } else {
                vec!["-e"]
            },
        ),
        (
            "alacritty",
            if hold_on_exit {
                vec!["--hold", "-e"]
            } else {
                vec!["-e"]
            },
        ),
        (
            "kitty",
            if hold_on_exit {
                vec!["--hold", "--"]
            } else {
                vec!["--"]
            },
        ),
        ("xdg-terminal-exec", vec!["--"]),
    ];
    let has_setsid = command_exists("setsid");
    for (term, flags) in candidates {
        if command_exists(term) {
            let mut full: Vec<&str> = Vec::new();
            if has_setsid {
                full.push(term);
            }
            full.extend_from_slice(flags);
            full.extend_from_slice(cmd);

            let program = if has_setsid { "setsid" } else { *term };
            Command::new(program)
                .args(&full)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("failed to open {term}: {e}"))?;
            return Ok(if hold_on_exit { "opened-logs" } else { "opened-shell" }.into());
        }
    }
    Err("no supported terminal emulator found".into())
}

fn command_exists(name: &str) -> bool {
    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            if Path::new(dir).join(name).is_file() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_only_local_or_ip_urls() {
        assert!(validate_local_url("http://localhost:3000").is_ok());
        assert!(validate_local_url("http://192.168.1.42:5173").is_ok());
        assert!(validate_local_url("https://127.0.0.1:8443").is_ok());
        assert!(validate_local_url("http://evil.example.com:80").is_err());
        assert!(validate_local_url("javascript:alert(1)").is_err());
        assert!(validate_local_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn rejects_flag_and_shell_injection_identifiers() {
        assert!(validate_identifier("pg-dev_1").is_ok());
        assert!(validate_identifier("docker.service").is_ok());
        assert!(validate_identifier("--exec=bad").is_err());
        assert!(validate_identifier("foo;rm -rf /").is_err());
        assert!(validate_identifier("bar$(id)").is_err());
    }

    #[test]
    fn matches_hyprland_client_by_pid_ancestry() {
        let sample = r#"[
  {
    "address": "0x55aa1122",
    "pid": 2000
  },
  {
    "address": "0x55aa3344",
    "pid": 5000
  }
]"#;
        let addr = find_matching_hypr_address(sample, &[9001, 7000, 5000, 1]);
        assert_eq!(addr.as_deref(), Some("0x55aa3344"));
    }

    #[test]
    fn parses_http_status_lines_for_health_probe() {
        assert_eq!(
            parse_http_status_line(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"),
            Some("200 OK".into())
        );
        assert_eq!(
            parse_http_status_line(b"HTTP/1.1 404 Not Found\r\n"),
            Some("404 Not Found".into())
        );
        assert_eq!(parse_http_status_line(b"\x00\x00not-http"), None);
    }
}
