//! Docker / Podman container inspection & host-port correlation.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::json::Json;

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,   // "running" | "exited" | "paused" | ...
    pub status: String,  // "Up 2 hours (healthy)"
    pub ports: Vec<u16>, // published host ports
    pub ports_raw: String,
    pub engine: String,  // "docker" | "podman"
    pub compose_project: String,
    pub compose_service: String,
}

#[derive(Debug, Clone)]
pub struct ContainersState {
    pub engine: String,
    pub available: bool,
    pub running_count: usize,
    pub items: Vec<ContainerInfo>,
    pub port_map: HashMap<u16, String>,
}

impl ContainersState {
    pub fn collect() -> Self {
        // Fast path: talk HTTP/1.1 directly over /run/docker.sock or podman.sock
        // (~2-14ms, zero Go CLI startup overhead).
        if let Ok(state) = crate::docker_sock::list_containers() {
            return state;
        }

        let engine = match detect_engine() {
            Some(e) => e,
            None => {
                return Self {
                    engine: String::new(),
                    available: false,
                    running_count: 0,
                    items: Vec::new(),
                    port_map: HashMap::new(),
                };
            }
        };

        let out = match Command::new(engine)
            .args([
                "ps",
                "-a",
                "--no-trunc=false",
                "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}",
            ])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => {
                return Self {
                    engine: engine.into(),
                    available: false,
                    running_count: 0,
                    items: Vec::new(),
                    port_map: HashMap::new(),
                };
            }
        };

        let text = String::from_utf8_lossy(&out.stdout);
        parse_container_lines(&text, engine)
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("engine", Json::s(self.engine.clone())),
            ("available", Json::Bool(self.available)),
            ("runningCount", Json::Uint(self.running_count as u64)),
            (
                "items",
                Json::Array(
                    self.items
                        .iter()
                        .map(|c| {
                            Json::Object(vec![
                                ("id", Json::s(c.id.clone())),
                                ("name", Json::s(c.name.clone())),
                                ("image", Json::s(c.image.clone())),
                                ("state", Json::s(c.state.clone())),
                                ("status", Json::s(c.status.clone())),
                                ("portsRaw", Json::s(c.ports_raw.clone())),
                                (
                                    "ports",
                                    Json::Array(
                                        c.ports.iter().map(|p| Json::Uint(*p as u64)).collect(),
                                    ),
                                ),
                                ("engine", Json::s(c.engine.clone())),
                                ("composeProject", Json::s(c.compose_project.clone())),
                                ("composeService", Json::s(c.compose_service.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

pub fn detect_engine() -> Option<&'static str> {
    if Path::new("/run/docker.sock").exists() || Path::new("/var/run/docker.sock").exists() {
        return Some("docker");
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        if Path::new(&format!("{xdg}/docker.sock")).exists() {
            return Some("docker");
        }
        if Path::new(&format!("{xdg}/podman/podman.sock")).exists() {
            return Some("podman");
        }
    }
    None
}

pub fn parse_container_lines(raw: &str, engine: &str) -> ContainersState {
    let mut items = Vec::new();
    let mut port_map = HashMap::new();
    let mut running_count = 0usize;

    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 5 {
            continue;
        }
        let id = cols[0].trim().to_string();
        let name = cols[1].trim().to_string();
        let image = cols[2].trim().to_string();
        let state = cols[3].trim().to_ascii_lowercase();
        let status = cols[4].trim().to_string();
        let ports_raw = cols.get(5).copied().unwrap_or("").trim().to_string();
        let compose_project = cols.get(6).copied().unwrap_or("").trim().to_string();
        let compose_service = cols.get(7).copied().unwrap_or("").trim().to_string();
        let ports = extract_host_ports(&ports_raw);

        if state == "running" {
            running_count += 1;
            for p in &ports {
                port_map.entry(*p).or_insert_with(|| name.clone());
            }
        }

        items.push(ContainerInfo {
            id,
            name,
            image,
            state,
            status,
            ports,
            ports_raw,
            engine: engine.into(),
            compose_project,
            compose_service,
        });
    }

    // Running containers first, then alphabetical by name
    items.sort_by(|a, b| {
        let ra = if a.state == "running" { 0 } else { 1 };
        let rb = if b.state == "running" { 0 } else { 1 };
        ra.cmp(&rb).then_with(|| a.name.cmp(&b.name))
    });

    ContainersState {
        engine: engine.into(),
        available: true,
        running_count,
        items,
        port_map,
    }
}

/// Extract published host ports from docker port mappings like
/// `0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp, 127.0.0.1:8080->80/tcp`.
pub fn extract_host_ports(raw: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        let Some((left, _right)) = part.split_once("->") else { continue };
        let Some(port_str) = left.rsplit(':').next() else { continue };
        let port_str = port_str.split('-').next().unwrap_or(port_str);
        if let Ok(p) = port_str.parse::<u16>()
            && !out.contains(&p)
        {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_deduped_host_ports() {
        let raw = "0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp, 127.0.0.1:8080->80/tcp, 6379/tcp";
        assert_eq!(extract_host_ports(raw), vec![5432, 8080]);
    }

    #[test]
    fn parses_docker_ps_rows() {
        let raw = "abc123def456\tpg-dev\tpostgres:16\trunning\tUp 3 hours\t0.0.0.0:5432->5432/tcp\n\
                   999888777666\tredis-old\tredis:7\texited\tExited (0) 2 days ago\t\n";
        let state = parse_container_lines(raw, "docker");
        assert_eq!(state.running_count, 1);
        assert_eq!(state.items.len(), 2);
        assert_eq!(state.port_map.get(&5432), Some(&"pg-dev".to_string()));
    }
}
