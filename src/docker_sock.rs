//! Zero-dependency direct HTTP/1.1 client over Docker / Podman UNIX sockets.
//! Eliminates cold Go CLI startup for container listing, start/stop/restart,
//! and instant inline log tailing.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::docker::{ContainerInfo, ContainersState};
use crate::json::{Value, parse_json};

#[derive(Debug, Clone)]
pub struct SocketEndpoint {
    pub engine: &'static str,
    pub path: PathBuf,
}

impl SocketEndpoint {
    /// Return CLI flags pinning docker/podman strictly to this local UNIX socket
    /// so `DOCKER_HOST` or an active remote CLI context can never be used.
    pub fn cli_host_args(&self) -> Vec<String> {
        let uri = format!("unix://{}", self.path.display());
        if self.engine == "podman" {
            vec!["--url".into(), uri]
        } else {
            vec!["-H".into(), uri]
        }
    }
}

pub fn detect_socket() -> Option<SocketEndpoint> {
    if Path::new("/run/docker.sock").exists() {
        return Some(SocketEndpoint {
            engine: "docker",
            path: PathBuf::from("/run/docker.sock"),
        });
    }
    if Path::new("/var/run/docker.sock").exists() {
        return Some(SocketEndpoint {
            engine: "docker",
            path: PathBuf::from("/var/run/docker.sock"),
        });
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let rootless_docker = PathBuf::from(format!("{xdg}/docker.sock"));
        if rootless_docker.exists() {
            return Some(SocketEndpoint {
                engine: "docker",
                path: rootless_docker,
            });
        }
        let podman = PathBuf::from(format!("{xdg}/podman/podman.sock"));
        if podman.exists() {
            return Some(SocketEndpoint {
                engine: "podman",
                path: podman,
            });
        }
    }
    None
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn unix_http_request(
    sock_path: &Path,
    method: &str,
    path: &str,
    timeout_secs: u64,
) -> Result<HttpResponse, String> {
    let mut stream =
        UnixStream::connect(sock_path).map_err(|e| format!("socket connect failed: {e}"))?;
    let timeout = Some(Duration::from_secs(timeout_secs));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("socket write failed: {e}"))?;

    let mut raw = Vec::with_capacity(8192);
    let mut buf = [0u8; 8192];
    let max_bytes: usize = 2 * 1024 * 1024; // 2 MB hard safety cap
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min(max_bytes.saturating_sub(raw.len()));
                raw.extend_from_slice(&buf[..take]);
                if raw.len() >= max_bytes {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("socket read failed: {e}")),
        }
    }

    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response (missing header separator)".to_string())?;
    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "non-utf8 HTTP header".to_string())?;

    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid HTTP status line: {status_line}"))?;

    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("transfer-encoding")
            && v.to_ascii_lowercase().contains("chunked")
        {
            is_chunked = true;
        }
    }

    let raw_body = &raw[header_end + 4..];
    let body = if is_chunked {
        decode_chunked(raw_body)
    } else {
        raw_body.to_vec()
    };

    Ok(HttpResponse { status, body })
}

pub fn decode_chunked(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0;
    while pos < input.len() {
        let Some(rel_crlf) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = std::str::from_utf8(&input[pos..pos + rel_crlf]).unwrap_or("");
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex, 16) else {
            break;
        };
        pos += rel_crlf + 2;
        if chunk_len == 0 {
            break;
        }
        let end = (pos + chunk_len).min(input.len());
        out.extend_from_slice(&input[pos..end]);
        pos = end;
        if input.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        }
    }
    out
}

pub fn list_containers() -> Result<ContainersState, String> {
    let ep = detect_socket().ok_or_else(|| "no container socket".to_string())?;
    list_containers_on(&ep)
}

pub fn list_containers_on(ep: &SocketEndpoint) -> Result<ContainersState, String> {
    let resp = unix_http_request(&ep.path, "GET", "/containers/json?all=1", 3)?;
    if resp.status != 200 {
        return Err(format!("daemon returned HTTP {}", resp.status));
    }
    let body_str = String::from_utf8_lossy(&resp.body);
    parse_docker_api_containers(&body_str, ep.engine)
}

pub fn parse_docker_api_containers(raw: &str, engine: &str) -> Result<ContainersState, String> {
    let parsed = parse_json(raw)?;
    let arr = parsed
        .as_array()
        .ok_or_else(|| "expected JSON array from /containers/json".to_string())?;

    let mut items = Vec::with_capacity(arr.len());
    let mut port_map: HashMap<u16, String> = HashMap::new();
    let mut running_count = 0usize;

    for obj in arr {
        let full_id = obj.get("Id").and_then(Value::as_str).unwrap_or("");
        let id = full_id.chars().take(12).collect::<String>();
        let name = obj
            .get("Names")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_else(|| id.clone());
        let image = obj
            .get("Image")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let state = obj
            .get("State")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        let status = obj
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let mut ports: Vec<u16> = Vec::new();
        let mut raw_parts: Vec<String> = Vec::new();
        if let Some(port_arr) = obj.get("Ports").and_then(Value::as_array) {
            for p in port_arr {
                let priv_port = p.get("PrivatePort").and_then(Value::as_u64).unwrap_or(0) as u16;
                let pub_port = p.get("PublicPort").and_then(Value::as_u64).unwrap_or(0) as u16;
                let ip = p.get("IP").and_then(Value::as_str).unwrap_or("");
                let proto = p.get("Type").and_then(Value::as_str).unwrap_or("tcp");
                if pub_port > 0 {
                    if !ports.contains(&pub_port) {
                        ports.push(pub_port);
                    }
                    let bind = if ip.is_empty() { "0.0.0.0" } else { ip };
                    raw_parts.push(format!("{bind}:{pub_port}->{priv_port}/{proto}"));
                }
            }
        }
        ports.sort_unstable();

        if state == "running" {
            running_count += 1;
            for p in &ports {
                port_map.entry(*p).or_insert_with(|| name.clone());
            }
        }

        let labels = obj.get("Labels");
        let compose_project = labels
            .and_then(|l| l.get("com.docker.compose.project"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let compose_service = labels
            .and_then(|l| l.get("com.docker.compose.service"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        items.push(ContainerInfo {
            id,
            name,
            image,
            state,
            status,
            ports,
            ports_raw: raw_parts.join(", "),
            engine: engine.into(),
            compose_project,
            compose_service,
        });
    }

    items.sort_by(|a, b| {
        let ra = if a.state == "running" { 0 } else { 1 };
        let rb = if b.state == "running" { 0 } else { 1 };
        ra.cmp(&rb).then_with(|| a.name.cmp(&b.name))
    });

    Ok(ContainersState {
        engine: engine.into(),
        available: true,
        running_count,
        items,
        port_map,
    })
}

pub fn lifecycle_on(ep: &SocketEndpoint, action: &str, id: &str) -> Result<String, String> {
    let path = match action {
        "start" => format!("/containers/{id}/start"),
        "stop" => format!("/containers/{id}/stop?t=5"),
        "restart" => format!("/containers/{id}/restart?t=5"),
        _ => return Err(format!("unsupported action: {action}")),
    };
    let resp = unix_http_request(&ep.path, "POST", &path, 15)?;
    match resp.status {
        204 | 200 => Ok(format!("{action}ed")),
        304 => Ok(format!("already {action}ed")),
        code => {
            let msg = parse_json(&String::from_utf8_lossy(&resp.body))
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(|s| s.to_string()))
                .unwrap_or_else(|| format!("daemon HTTP {code}"));
            Err(msg)
        }
    }
}

pub fn tail_logs(id: &str, tail: u32) -> Result<String, String> {
    let ep = detect_socket().ok_or_else(|| "no container socket".to_string())?;
    tail_logs_on(&ep, id, tail)
}

pub fn tail_logs_on(ep: &SocketEndpoint, id: &str, tail: u32) -> Result<String, String> {
    let safe_tail = tail.clamp(10, 500);
    let path = format!("/containers/{id}/logs?stdout=1&stderr=1&tail={safe_tail}");
    let resp = unix_http_request(&ep.path, "GET", &path, 5)?;
    if resp.status != 200 {
        let msg = parse_json(&String::from_utf8_lossy(&resp.body))
            .ok()
            .and_then(|v| v.get("message").and_then(Value::as_str).map(|s| s.to_string()))
            .unwrap_or_else(|| format!("daemon HTTP {}", resp.status));
        return Err(msg);
    }
    let decoded = decode_docker_log_stream(&resp.body);
    Ok(strip_ansi(&decoded))
}

/// Decode Docker's 8-byte multiplexed stdout/stderr frame headers
/// (`[stream_type (1|2), 0, 0, 0, be_u32_len]`). Falls back seamlessly to raw
/// UTF-8 text for TTY containers that omit frame headers.
pub fn decode_docker_log_stream(raw: &[u8]) -> String {
    if raw.len() >= 8 && matches!(raw[0], 1 | 2) && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
        let mut out = Vec::with_capacity(raw.len());
        let mut pos = 0;
        let mut valid_frames = true;
        while pos + 8 <= raw.len() {
            let stream_id = raw[pos];
            if !matches!(stream_id, 0 | 1 | 2) || raw[pos + 1] != 0 || raw[pos + 2] != 0 || raw[pos + 3] != 0 {
                valid_frames = false;
                break;
            }
            let frame_len = u32::from_be_bytes([
                raw[pos + 4],
                raw[pos + 5],
                raw[pos + 6],
                raw[pos + 7],
            ]) as usize;
            pos += 8;
            let end = pos.saturating_add(frame_len).min(raw.len());
            out.extend_from_slice(&raw[pos..end]);
            pos = end;
        }
        if valid_frames && !out.is_empty() {
            return String::from_utf8_lossy(&out).into_owned();
        }
    }
    String::from_utf8_lossy(raw).into_owned()
}

pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for nc in chars.by_ref() {
                    if ('@'..='~').contains(&nc) {
                        break;
                    }
                }
            }
            continue;
        }
        if c == '\r' {
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_http_chunked_encoding() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(raw), b"hello world");
    }

    #[test]
    fn decodes_multiplexed_docker_log_frames_and_strips_ansi() {
        let msg = b"\x1b[32mREADY\x1b[0m on :4566\n";
        let mut frame = vec![1, 0, 0, 0];
        frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        frame.extend_from_slice(msg);
        let text = strip_ansi(&decode_docker_log_stream(&frame));
        assert_eq!(text, "READY on :4566\n");
    }

    #[test]
    fn parses_docker_api_container_list() {
        let raw = r#"[
          {"Id":"18f4ac219e3faabbccdd","Names":["/floci"],"Image":"floci/floci:latest","State":"running","Status":"Up 3m","Ports":[{"IP":"0.0.0.0","PrivatePort":4566,"PublicPort":4566,"Type":"tcp"},{"IP":"::","PrivatePort":4566,"PublicPort":4566,"Type":"tcp"}]},
          {"Id":"24cef9584e1199887766","Names":["/kafka"],"Image":"apache/kafka:3.7.0","State":"exited","Status":"Exited (0)","Ports":[]}
        ]"#;
        let state = parse_docker_api_containers(raw, "docker").expect("ok");
        assert_eq!(state.running_count, 1);
        assert_eq!(state.items.len(), 2);
        assert_eq!(state.items[0].name, "floci");
        assert_eq!(state.items[0].id, "18f4ac219e3f");
        assert_eq!(state.items[0].ports, vec![4566]);
        assert_eq!(state.port_map.get(&4566), Some(&"floci".to_string()));
    }
}
