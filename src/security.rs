//! OS-level Linux security & hardening posture checks (zero root, read-only).

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

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
    // Query live runtime state from systemd (unprivileged) rather than trusting
    // static config files on disk when the firewall service is stopped.
    let states = query_firewall_services();
    let ufw_conf_enabled = fs::read_to_string("/etc/ufw/ufw.conf")
        .ok()
        .map(|raw| raw.lines().any(|l| l.trim() == "ENABLED=yes"));
    let has_any_config = Path::new("/etc/ufw/ufw.conf").exists()
        || Path::new("/etc/nftables.conf").exists();

    evaluate_firewall_state(states, ufw_conf_enabled, has_any_config)
}

fn query_firewall_services() -> Option<(String, String, String)> {
    let out = Command::new("systemctl")
        .args(["is-active", "ufw.service", "nftables.service", "firewalld.service"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines().map(|l| l.trim().to_string());
    let ufw = lines.next()?;
    let nft = lines.next().unwrap_or_default();
    let fwld = lines.next().unwrap_or_default();
    // Ignore empty output when systemd bus is unavailable (e.g. non-systemd container)
    if ufw.is_empty() && nft.is_empty() && fwld.is_empty() {
        return None;
    }
    Some((ufw, nft, fwld))
}

pub fn evaluate_firewall_state(
    service_states: Option<(String, String, String)>,
    ufw_conf_enabled: Option<bool>,
    has_any_config: bool,
) -> SecurityCheck {
    let Some((ufw, nft, fwld)) = service_states else {
        return SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "warn",
            detail: "Cannot verify live firewall service state (systemd unavailable)".into(),
        };
    };

    if ufw == "active" {
        return match ufw_conf_enabled {
            Some(true) => SecurityCheck {
                id: "firewall",
                label: "Host Firewall",
                status: "pass",
                detail: "ufw.service active and ENABLED=yes".into(),
            },
            Some(false) => SecurityCheck {
                id: "firewall",
                label: "Host Firewall",
                status: "fail",
                detail: "ufw.service active but ENABLED=no in /etc/ufw/ufw.conf".into(),
            },
            None => SecurityCheck {
                id: "firewall",
                label: "Host Firewall",
                status: "warn",
                detail: "ufw.service active, unable to confirm ENABLED=yes".into(),
            },
        };
    }

    if nft == "active" {
        return SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "pass",
            detail: "nftables.service active".into(),
        };
    }

    if fwld == "active" {
        return SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "pass",
            detail: "firewalld.service active".into(),
        };
    }

    if has_any_config {
        SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "fail",
            detail: format!(
                "Firewall config present but services inactive (ufw:{ufw}, nft:{nft}, firewalld:{fwld})"
            ),
        }
    } else {
        SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "warn",
            detail: "No active firewall service (ufw/nftables/firewalld)".into(),
        }
    }
}

fn check_luks_encryption() -> SecurityCheck {
    // Verify the actual mounted `/` root filesystem by resolving its backing
    // block device from /proc/self/mountinfo and walking /sys/class/block/*/dm/uuid
    // for a kernel dm-crypt ("CRYPT-...") UUID — never trusting /proc/cmdline or
    // unrelated /dev/mapper/* names.
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: "Unable to read /proc/self/mountinfo".into(),
        };
    };
    let Some((maj_min, source)) = extract_root_mount_source(&mountinfo) else {
        return SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: "Could not identify mounted / root device".into(),
        };
    };

    let Some(block_name) = resolve_block_device_name(&maj_min, &source) else {
        return SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: format!("Root / mount source ({source}) is not a dm-crypt block device"),
        };
    };

    let mut visited = HashSet::new();
    if let Some((dm_dev, uuid)) = find_crypt_dm_ancestor(&block_name, &mut visited, 0) {
        let kind = if uuid.starts_with("CRYPT-LUKS2-") {
            "LUKS2"
        } else if uuid.starts_with("CRYPT-LUKS1-") {
            "LUKS1"
        } else {
            "dm-crypt"
        };
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "pass",
            detail: format!("Root / backed by {kind} dm-crypt ({dm_dev})"),
        }
    } else {
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: format!("Root / mounted on {block_name} (no dm-crypt ancestor)"),
        }
    }
}

/// Extract `(major:minor, mount_source)` for the active `/` mount point from
/// `/proc/self/mountinfo` (taking the last matching `/` entry in mount order).
pub fn extract_root_mount_source(mountinfo: &str) -> Option<(String, String)> {
    let mut found: Option<(String, String)> = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields: Vec<&str> = left.split_whitespace().collect();
        if left_fields.len() < 5 || left_fields[4] != "/" {
            continue;
        }
        let right_fields: Vec<&str> = right.split_whitespace().collect();
        if right_fields.len() < 2 {
            continue;
        }
        let maj_min = left_fields[2].to_string();
        let source = right_fields[1].to_string();
        found = Some((maj_min, source));
    }
    found
}

fn resolve_block_device_name(maj_min: &str, source: &str) -> Option<String> {
    if source.starts_with("/dev/")
        && let Ok(canon) = fs::canonicalize(source)
        && let Some(name) = canon.file_name().and_then(|n| n.to_str())
        && Path::new("/sys/class/block").join(name).exists()
    {
        return Some(name.to_string());
    }
    if !maj_min.starts_with("0:")
        && let Ok(canon) = fs::canonicalize(format!("/sys/dev/block/{maj_min}"))
        && let Some(name) = canon.file_name().and_then(|n| n.to_str())
    {
        return Some(name.to_string());
    }
    None
}

pub fn is_crypt_dm_uuid(uuid: &str) -> bool {
    uuid.trim().starts_with("CRYPT-")
}

fn find_crypt_dm_ancestor(
    dev_name: &str,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Option<(String, String)> {
    if depth > 8 || !visited.insert(dev_name.to_string()) {
        return None;
    }
    let block_dir = Path::new("/sys/class/block").join(dev_name);
    if let Ok(uuid) = fs::read_to_string(block_dir.join("dm/uuid"))
        && is_crypt_dm_uuid(&uuid)
    {
        return Some((dev_name.to_string(), uuid.trim().to_string()));
    }
    let slaves_dir = block_dir.join("slaves");
    if let Ok(entries) = fs::read_dir(slaves_dir) {
        for entry in entries.flatten() {
            let slave_name = entry.file_name().to_string_lossy().into_owned();
            if let Some(hit) = find_crypt_dm_ancestor(&slave_name, visited, depth + 1) {
                return Some(hit);
            }
        }
    }
    None
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

    #[test]
    fn firewall_fails_when_config_exists_but_services_inactive() {
        let chk = evaluate_firewall_state(
            Some(("inactive".into(), "inactive".into(), "inactive".into())),
            Some(true),
            true,
        );
        assert_eq!(chk.status, "fail");

        let ok = evaluate_firewall_state(
            Some(("active".into(), "inactive".into(), "inactive".into())),
            Some(true),
            true,
        );
        assert_eq!(ok.status, "pass");

        let no_systemd = evaluate_firewall_state(None, Some(true), true);
        assert_eq!(no_systemd.status, "warn");
    }

    #[test]
    fn parses_root_mount_source_and_dm_crypt_uuid() {
        let mi = "29 1 0:27 /@ / rw,relatime shared:1 - btrfs /dev/mapper/root rw,compress=zstd:3\n\
                  30 29 0:28 /@home /home rw,relatime - btrfs /dev/mapper/root rw\n";
        assert_eq!(
            extract_root_mount_source(mi),
            Some(("0:27".into(), "/dev/mapper/root".into()))
        );
        assert!(is_crypt_dm_uuid("CRYPT-LUKS2-6402632d2ba5443f8ff4043762fb3bcf-root\n"));
        assert!(!is_crypt_dm_uuid("LVM-abcd1234"));
    }
}
