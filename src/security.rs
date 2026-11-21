//! OS-level Linux security & hardening posture checks (zero root, read-only).

use std::fs;
use std::path::Path;

use crate::json::Json;
use crate::proc_ports::ListeningPort;
use crate::traffic::TrafficState;

#[derive(Debug, Clone)]
pub struct SecurityCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: &'static str, // "pass" | "warn" | "fail"
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct SecurityState {
    pub pass_count: usize,
    pub warn_count: usize,
    pub fail_count: usize,
    pub critical_count: usize,
    pub checks: Vec<SecurityCheck>,
}

impl SecurityState {
    pub fn collect(ports: &[ListeningPort], traffic: &TrafficState) -> Self {
        let mut checks = Vec::with_capacity(11);

        checks.push(check_firewall());
        checks.push(check_luks_encryption());
        checks.push(check_aslr());
        checks.push(check_ptrace_scope());
        checks.push(check_unprivileged_bpf());
        checks.push(check_kptr_and_dmesg());
        checks.push(check_rp_filter());
        checks.push(check_kernel_reboot_drift());
        checks.push(check_ssh_exposure(ports));
        checks.push(check_exposed_data_ports(ports));
        checks.push(check_runtime_traffic_threats(traffic));

        let pass_count = checks.iter().filter(|c| c.status == "pass").count();
        let warn_count = checks.iter().filter(|c| c.status == "warn").count();
        let fail_count = checks.iter().filter(|c| c.status == "fail").count();
        let critical_count = traffic.critical_alerts.len() + fail_count;

        // Sort issues first (fail -> warn -> pass) so risks are immediately visible
        checks.sort_by(|a, b| {
            let rank = |s: &str| match s {
                "fail" => 0,
                "warn" => 1,
                _ => 2,
            };
            rank(a.status).cmp(&rank(b.status))
        });

        Self {
            pass_count,
            warn_count,
            fail_count,
            critical_count,
            checks,
        }
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("passCount", Json::Uint(self.pass_count as u64)),
            ("warnCount", Json::Uint(self.warn_count as u64)),
            ("failCount", Json::Uint(self.fail_count as u64)),
            ("criticalCount", Json::Uint(self.critical_count as u64)),
            (
                "checks",
                Json::Array(
                    self.checks
                        .iter()
                        .map(|c| {
                            Json::Object(vec![
                                ("id", Json::s(c.id)),
                                ("label", Json::s(c.label)),
                                ("status", Json::s(c.status)),
                                ("detail", Json::s(c.detail.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

fn read_sysctl_u32(path: &str) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse::<u32>().ok()
}

fn check_firewall() -> SecurityCheck {
    if let Ok(raw) = fs::read_to_string("/etc/ufw/ufw.conf") {
        let enabled = raw.lines().any(|l| l.trim() == "ENABLED=yes");
        if enabled {
            return SecurityCheck {
                id: "firewall",
                label: "Host Firewall",
                status: "pass",
                detail: "UFW enabled (/etc/ufw/ufw.conf)".into(),
            };
        }
        return SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "fail",
            detail: "UFW installed but ENABLED=no".into(),
        };
    }
    if Path::new("/etc/nftables.conf").exists() {
        return SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "pass",
            detail: "nftables configuration present".into(),
        };
    }
    SecurityCheck {
        id: "firewall",
        label: "Host Firewall",
        status: "warn",
        detail: "No UFW or nftables config detected".into(),
    }
}

fn check_luks_encryption() -> SecurityCheck {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    if cmdline.contains("cryptdevice=") || cmdline.contains("rd.luks") || Path::new("/dev/mapper/root").exists() {
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "pass",
            detail: "LUKS dm-crypt root active".into(),
        }
    } else {
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: "Root partition not on LUKS dm-crypt".into(),
        }
    }
}

fn check_aslr() -> SecurityCheck {
    match read_sysctl_u32("/proc/sys/kernel/randomize_va_space") {
        Some(2) => SecurityCheck {
            id: "aslr",
            label: "Kernel ASLR",
            status: "pass",
            detail: "Full randomization (randomize_va_space=2)".into(),
        },
        Some(v) => SecurityCheck {
            id: "aslr",
            label: "Kernel ASLR",
            status: "fail",
            detail: format!("Weak ASLR (randomize_va_space={v})"),
        },
        None => SecurityCheck {
            id: "aslr",
            label: "Kernel ASLR",
            status: "warn",
            detail: "Unreadable sysctl".into(),
        },
    }
}

fn check_ptrace_scope() -> SecurityCheck {
    match read_sysctl_u32("/proc/sys/kernel/yama/ptrace_scope") {
        Some(v) if v >= 1 => SecurityCheck {
            id: "ptrace",
            label: "Ptrace Isolation",
            status: "pass",
            detail: format!("Yama restricted (ptrace_scope={v})"),
        },
        Some(0) => SecurityCheck {
            id: "ptrace",
            label: "Ptrace Isolation",
            status: "warn",
            detail: "Unrestricted ptrace_scope=0".into(),
        },
        _ => SecurityCheck {
            id: "ptrace",
            label: "Ptrace Isolation",
            status: "warn",
            detail: "Yama ptrace sysctl unavailable".into(),
        },
    }
}

fn check_unprivileged_bpf() -> SecurityCheck {
    match read_sysctl_u32("/proc/sys/kernel/unprivileged_bpf_disabled") {
        Some(v) if v >= 1 => SecurityCheck {
            id: "bpf",
            label: "eBPF Lock",
            status: "pass",
            detail: format!("Unprivileged eBPF disabled ({v})"),
        },
        Some(0) => SecurityCheck {
            id: "bpf",
            label: "eBPF Lock",
            status: "warn",
            detail: "Unprivileged eBPF allowed (0)".into(),
        },
        _ => SecurityCheck {
            id: "bpf",
            label: "eBPF Lock",
            status: "warn",
            detail: "eBPF sysctl unavailable".into(),
        },
    }
}

fn check_kptr_and_dmesg() -> SecurityCheck {
    let kptr = read_sysctl_u32("/proc/sys/kernel/kptr_restrict").unwrap_or(0);
    let dmesg = read_sysctl_u32("/proc/sys/kernel/dmesg_restrict").unwrap_or(0);
    if kptr >= 1 && dmesg >= 1 {
        SecurityCheck {
            id: "kptr",
            label: "Kernel Info Hide",
            status: "pass",
            detail: format!("kptr_restrict={kptr}, dmesg_restrict={dmesg}"),
        }
    } else {
        SecurityCheck {
            id: "kptr",
            label: "Kernel Info Hide",
            status: "warn",
            detail: format!("kptr_restrict={kptr}, dmesg_restrict={dmesg}"),
        }
    }
}

fn check_rp_filter() -> SecurityCheck {
    match read_sysctl_u32("/proc/sys/net/ipv4/conf/all/rp_filter") {
        Some(1) => SecurityCheck {
            id: "rpfilter",
            label: "Anti-Spoof Filter",
            status: "pass",
            detail: "Strict reverse-path filtering (rp_filter=1)".into(),
        },
        Some(2) => SecurityCheck {
            id: "rpfilter",
            label: "Anti-Spoof Filter",
            status: "pass",
            detail: "Loose reverse-path filtering (rp_filter=2)".into(),
        },
        _ => SecurityCheck {
            id: "rpfilter",
            label: "Anti-Spoof Filter",
            status: "warn",
            detail: "rp_filter disabled (0)".into(),
        },
    }
}

fn check_kernel_reboot_drift() -> SecurityCheck {
    let running = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    if running.is_empty() {
        return SecurityCheck {
            id: "kernel-drift",
            label: "Kernel Drift",
            status: "warn",
            detail: "Could not read running kernel".into(),
        };
    }
    let mod_dir = format!("/usr/lib/modules/{running}");
    if Path::new(&mod_dir).is_dir() {
        SecurityCheck {
            id: "kernel-drift",
            label: "Kernel Sync",
            status: "pass",
            detail: format!("Running {running} matches installed modules"),
        }
    } else {
        SecurityCheck {
            id: "kernel-drift",
            label: "Kernel Drift",
            status: "warn",
            detail: format!("Running {running} replaced on disk — reboot recommended"),
        }
    }
}

fn check_ssh_exposure(ports: &[ListeningPort]) -> SecurityCheck {
    let ssh_lan = ports
        .iter()
        .find(|p| p.port == 22 && p.exposed_lan);
    if let Some(p) = ssh_lan {
        SecurityCheck {
            id: "ssh",
            label: "SSH Exposure",
            status: "warn",
            detail: format!("SSH :22 listening on {} (ensure key-only auth)", p.bind_addr),
        }
    } else {
        SecurityCheck {
            id: "ssh",
            label: "SSH Exposure",
            status: "pass",
            detail: "No public/LAN SSH :22 listener".into(),
        }
    }
}

fn check_exposed_data_ports(ports: &[ListeningPort]) -> SecurityCheck {
    let exposed: Vec<String> = ports
        .iter()
        .filter(|p| p.category == "data" && p.exposed_lan)
        .map(|p| format!(":{} {}", p.port, p.framework))
        .collect();
    if exposed.is_empty() {
        SecurityCheck {
            id: "data-bind",
            label: "Data Port Scope",
            status: "pass",
            detail: "No DB/broker bound to 0.0.0.0".into(),
        }
    } else {
        SecurityCheck {
            id: "data-bind",
            label: "LAN Data Exposure",
            status: "warn",
            detail: format!("Bound to 0.0.0.0: {}", exposed.join(", ")),
        }
    }
}

fn check_runtime_traffic_threats(traffic: &TrafficState) -> SecurityCheck {
    if !traffic.critical_alerts.is_empty() {
        SecurityCheck {
            id: "net-threat",
            label: "Runtime Traffic",
            status: "fail",
            detail: traffic.critical_alerts[0].clone(),
        }
    } else if traffic.cleartext_conns > 0 {
        SecurityCheck {
            id: "net-threat",
            label: "Runtime Traffic",
            status: "warn",
            detail: format!("{} cleartext public-internet connection(s)", traffic.cleartext_conns),
        }
    } else {
        SecurityCheck {
            id: "net-threat",
            label: "Runtime Traffic",
            status: "pass",
            detail: format!(
                "{} internet · {} LAN · 0 suspicious binaries",
                traffic.internet_conns, traffic.lan_conns
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_exposed_data_services() {
        let port = ListeningPort {
            port: 5432,
            bind_addr: "0.0.0.0".into(),
            exposed_lan: true,
            pid: 99,
            ppid: 1,
            uid: 1000,
            owned: true,
            comm: "postgres".into(),
            framework: "PostgreSQL".into(),
            category: "data".into(),
            is_http: false,
            project: String::new(),
            git_branch: String::new(),
            cwd: String::new(),
            mem_mb: 50.0,
            uptime_sec: 100,
            url: "localhost:5432".into(),
            lan_url: "192.168.0.10:5432".into(),
            container_name: String::new(),
        };
        let chk = check_exposed_data_ports(&[port]);
        assert_eq!(chk.status, "warn");
        assert!(chk.detail.contains(":5432 PostgreSQL"));
    }
}
