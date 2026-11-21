//! Systemd failed-unit detector and DevOps daemon health tracker.

use std::process::Command;

use crate::json::Json;

pub const TRACKED_UNITS: &[(&str, &str)] = &[
    ("docker.service", "Docker"),
    ("containerd.service", "containerd"),
    ("postgresql.service", "PostgreSQL"),
    ("redis.service", "Redis"),
    ("valkey.service", "Valkey"),
    ("mariadb.service", "MariaDB"),
    ("mysqld.service", "MySQL"),
    ("mongod.service", "MongoDB"),
    ("nginx.service", "Nginx"),
    ("caddy.service", "Caddy"),
    ("sshd.service", "OpenSSH"),
    ("tailscaled.service", "Tailscale"),
    ("ollama.service", "Ollama"),
    ("libvirtd.service", "Libvirt"),
    ("kafka.service", "Kafka"),
];

#[derive(Debug, Clone)]
pub struct ServiceItem {
    pub unit: String,
    pub label: String,
    pub active_state: String, // "active" | "inactive" | "failed" | "activating"
    pub sub_state: String,
    pub mem_mb: f64,
    pub is_user: bool,
}

#[derive(Debug, Clone)]
pub struct ServicesState {
    pub failed_count: usize,
    pub failed_units: Vec<ServiceItem>,
    pub daemons: Vec<ServiceItem>,
}

impl ServicesState {
    pub fn collect() -> Self {
        let mut failed_units = collect_failed(false);
        failed_units.extend(collect_failed(true));
        let failed_count = failed_units.len();
        let daemons = collect_tracked_daemons();

        Self {
            failed_count,
            failed_units,
            daemons,
        }
    }

    pub fn to_json(&self) -> Json {
        let serialize = |items: &[ServiceItem]| {
            Json::Array(
                items
                    .iter()
                    .map(|s| {
                        Json::Object(vec![
                            ("unit", Json::s(s.unit.clone())),
                            ("label", Json::s(s.label.clone())),
                            ("activeState", Json::s(s.active_state.clone())),
                            ("subState", Json::s(s.sub_state.clone())),
                            ("memMb", Json::Float(s.mem_mb)),
                            ("isUser", Json::Bool(s.is_user)),
                        ])
                    })
                    .collect(),
            )
        };
        Json::Object(vec![
            ("failedCount", Json::Uint(self.failed_count as u64)),
            ("failedUnits", serialize(&self.failed_units)),
            ("daemons", serialize(&self.daemons)),
        ])
    }
}

fn collect_failed(user_scope: bool) -> Vec<ServiceItem> {
    let mut cmd = Command::new("systemctl");
    if user_scope {
        cmd.arg("--user");
    }
    cmd.args(["--failed", "--no-legend", "--plain", "--no-pager"]);
    let Ok(out) = cmd.output() else { return Vec::new() };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut items = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let unit = cols[0].to_string();
        let label = unit.strip_suffix(".service").unwrap_or(&unit).to_string();
        items.push(ServiceItem {
            unit,
            label,
            active_state: cols[2].to_string(),
            sub_state: cols[3].to_string(),
            mem_mb: 0.0,
            is_user: user_scope,
        });
    }
    items
}

fn collect_tracked_daemons() -> Vec<ServiceItem> {
    let mut args: Vec<&str> = vec![
        "show",
        "--property=Id,LoadState,ActiveState,SubState,MemoryCurrent",
        "--no-pager",
    ];
    for (unit, _) in TRACKED_UNITS {
        args.push(unit);
    }
    let Ok(out) = Command::new("systemctl").args(&args).output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    parse_systemctl_show(&text)
}

pub fn parse_systemctl_show(raw: &str) -> Vec<ServiceItem> {
    let mut out = Vec::new();
    for block in raw.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        let mut id = "";
        let mut load = "";
        let mut active = "";
        let mut sub = "";
        let mut mem_bytes: u64 = 0;

        for line in block.lines() {
            if let Some(v) = line.strip_prefix("Id=") {
                id = v.trim();
            } else if let Some(v) = line.strip_prefix("LoadState=") {
                load = v.trim();
            } else if let Some(v) = line.strip_prefix("ActiveState=") {
                active = v.trim();
            } else if let Some(v) = line.strip_prefix("SubState=") {
                sub = v.trim();
            } else if let Some(v) = line.strip_prefix("MemoryCurrent=") {
                mem_bytes = v.trim().parse::<u64>().unwrap_or(0);
            }
        }

        // Only surface services actually installed on this machine
        if id.is_empty() || load != "loaded" {
            continue;
        }
        let label = TRACKED_UNITS
            .iter()
            .find(|(u, _)| *u == id)
            .map(|(_, l)| *l)
            .unwrap_or_else(|| id.strip_suffix(".service").unwrap_or(id));

        let mem_mb = if mem_bytes > 0 && mem_bytes < (1u64 << 50) {
            mem_bytes as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        };

        out.push(ServiceItem {
            unit: id.to_string(),
            label: label.to_string(),
            active_state: active.to_string(),
            sub_state: sub.to_string(),
            mem_mb,
            is_user: false,
        });
    }

    // Active/failed first, then inactive
    out.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "failed" => 0,
            "active" => 1,
            "activating" => 2,
            _ => 3,
        };
        rank(&a.active_state)
            .cmp(&rank(&b.active_state))
            .then_with(|| a.label.cmp(&b.label))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemctl_show_and_filters_uninstalled() {
        let raw = "\
Id=docker.service
LoadState=loaded
ActiveState=active
SubState=running
MemoryCurrent=52428800

Id=kafka.service
LoadState=not-found
ActiveState=inactive
SubState=dead
MemoryCurrent=[not set]
";
        let items = parse_systemctl_show(raw);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "Docker");
        assert_eq!(items[0].active_state, "active");
        assert!((items[0].mem_mb - 50.0).abs() < 0.01);
    }
}
