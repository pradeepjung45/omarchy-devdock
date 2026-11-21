//! Docker / Podman container inspection & host-port correlation.
//! Strictly targets local UNIX sockets so a local socket error never silently
//! switches to a remote `DOCKER_HOST` or CLI context.

use std::collections::HashMap;

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
        // Strictly talk HTTP/1.1 directly over the detected local UNIX socket
        // (/run/docker.sock, rootless docker.sock, or podman.sock). Never fall
        // back to ambient CLI contexts or DOCKER_HOST on local socket failure.
        if let Ok(state) = crate::docker_sock::list_containers() {
            return state;
        }

        let engine = crate::docker_sock::detect_socket()
            .map(|ep| ep.engine.to_string())
            .unwrap_or_default();
        Self {
            engine,
            available: false,
            running_count: 0,
            items: Vec::new(),
            port_map: HashMap::new(),
        }
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

#[cfg(test)]
mod tests {
    #[test]
    fn cli_host_args_pin_local_unix_socket() {
        let d = crate::docker_sock::SocketEndpoint {
            engine: "docker",
            path: std::path::PathBuf::from("/run/docker.sock"),
        };
        assert_eq!(d.cli_host_args(), vec!["-H", "unix:///run/docker.sock"]);

        let p = crate::docker_sock::SocketEndpoint {
            engine: "podman",
            path: std::path::PathBuf::from("/run/user/1000/podman/podman.sock"),
        };
        assert_eq!(
            p.cli_host_args(),
            vec!["--url", "unix:///run/user/1000/podman/podman.sock"]
        );
    }
}
