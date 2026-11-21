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
    pub status: &'static str, // "pass" | "info" | "warn" | "fail"
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct SecurityState {
    pub pass_count: usize,
    pub info_count: usize,
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
        let info_count = checks.iter().filter(|c| c.status == "info").count();
        let warn_count = checks.iter().filter(|c| c.status == "warn").count();
        let fail_count = checks.iter().filter(|c| c.status == "fail").count();
        let critical_count = traffic.critical_alerts.len() + fail_count;

        // Sort issues first (fail -> warn -> info -> pass) so risks & unverified items stand out
        checks.sort_by(|a, b| {
            let rank = |s: &str| match s {
                "fail" => 0,
                "warn" => 1,
                "info" => 2,
                _ => 3,
            };
            rank(a.status).cmp(&rank(b.status))
        });

        Self {
            pass_count,
            info_count,
            warn_count,
            fail_count,
            critical_count,
            checks,
        }
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("passCount", Json::Uint(self.pass_count as u64)),
            ("infoCount", Json::Uint(self.info_count as u64)),
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
    // Query live runtime state from systemd (unprivileged). Because inspecting
    // live kernel filtering rules (nft list ruleset / iptables / firewalld
    // active zones) requires elevated privileges, distinguish a running
    // firewall service ("info") from a verified filtering policy rather than
    // reporting a false "pass".
    let states = query_firewall_services();
    let ufw_conf_enabled = fs::read_to_string("/etc/ufw/ufw.conf")
        .ok()
        .map(|raw| raw.lines().any(|l| l.trim() == "ENABLED=yes"));
    let ufw_default_input = read_ufw_default_input_policy();
    let has_any_config = Path::new("/etc/ufw/ufw.conf").exists()
        || Path::new("/etc/nftables.conf").exists();

    evaluate_firewall_state(states, ufw_conf_enabled, ufw_default_input.as_deref(), has_any_config)
}

fn read_ufw_default_input_policy() -> Option<String> {
    let raw = fs::read_to_string("/etc/default/ufw").ok()?;
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("DEFAULT_INPUT_POLICY=") {
            return Some(rest.trim().trim_matches(|c| c == '"' || c == '\'').to_ascii_uppercase());
        }
    }
    None
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
    if ufw.is_empty() && nft.is_empty() && fwld.is_empty() {
        return None;
    }
    Some((ufw, nft, fwld))
}

pub fn evaluate_firewall_state(
    service_states: Option<(String, String, String)>,
    ufw_conf_enabled: Option<bool>,
    ufw_default_input: Option<&str>,
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
            Some(true) => {
                if ufw_default_input == Some("ACCEPT") {
                    SecurityCheck {
                        id: "firewall",
                        label: "Host Firewall",
                        status: "warn",
                        detail: "ufw.service running, but DEFAULT_INPUT_POLICY=ACCEPT".into(),
                    }
                } else {
                    let policy_note = match ufw_default_input {
                        Some(p) => format!("DEFAULT_INPUT_POLICY={p}; "),
                        None => String::new(),
                    };
                    SecurityCheck {
                        id: "firewall",
                        label: "Host Firewall",
                        status: "info",
                        detail: format!(
                            "ufw.service running ({policy_note}live rules require root to verify)"
                        ),
                    }
                }
            }
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
            status: "info",
            detail: "nftables.service running (live filtering policy requires root to verify)".into(),
        };
    }

    if fwld == "active" {
        return SecurityCheck {
            id: "firewall",
            label: "Host Firewall",
            status: "info",
            detail: "firewalld.service running (active zone policies require root to verify)".into(),
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
    // Verify EVERY data-bearing backing branch of the actual mounted `/` root
    // filesystem (including multi-device Btrfs volumes via /sys/fs/btrfs/*/devices
    // and composite dm/LVM/RAID slave graphs via /sys/class/block/*/slaves).
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: "Unable to read /proc/self/mountinfo".into(),
        };
    };
    let Some((fstype, maj_min, source)) = extract_root_mount_info(&mountinfo) else {
        return SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: "Could not identify mounted / root device".into(),
        };
    };

    let Some(primary_block) = resolve_block_device_name(&maj_min, &source) else {
        let src_label = if source.is_empty() { fstype.as_str() } else { source.as_str() };
        return SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: format!("Root / ({src_label}) is not a verified dm-crypt block device"),
        };
    };

    let root_devices = if fstype == "btrfs" {
        match enumerate_btrfs_backing_devices(&primary_block) {
            Some(devs) if !devs.is_empty() => devs,
            _ => {
                return SecurityCheck {
                    id: "luks",
                    label: "Disk Encryption",
                    status: "warn",
                    detail: format!(
                        "Root / is Btrfs ({primary_block}), unable to enumerate all backing devices"
                    ),
                };
            }
        }
    } else {
        vec![primary_block]
    };

    evaluate_block_encryption(&root_devices, read_sysfs_block_node)
}

/// Extract `(fstype, major:minor, mount_source)` for the active `/` mount point
/// from `/proc/self/mountinfo` (last matching `/` entry in mount order).
pub fn extract_root_mount_info(mountinfo: &str) -> Option<(String, String, String)> {
    let mut found: Option<(String, String, String)> = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields: Vec<&str> = left.split(' ').collect();
        if left_fields.len() < 5 || left_fields[4] != "/" {
            continue;
        }
        let right_fields: Vec<&str> = right.split(' ').collect();
        if right_fields.is_empty() {
            continue;
        }
        let maj_min = left_fields[2].to_string();
        let fstype = right_fields[0].to_string();
        let source = right_fields.get(1).copied().unwrap_or("").to_string();
        found = Some((fstype, maj_min, source));
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

fn enumerate_btrfs_backing_devices(primary_dev: &str) -> Option<Vec<String>> {
    let rd = fs::read_dir("/sys/fs/btrfs").ok()?;
    for entry in rd.flatten() {
        let dev_dir = entry.path().join("devices");
        if !dev_dir.is_dir() {
            continue;
        }
        let entries = fs::read_dir(&dev_dir).ok()?;
        let mut devs: Vec<String> = Vec::new();
        for d in entries.flatten() {
            devs.push(d.file_name().to_string_lossy().into_owned());
        }
        devs.sort();
        if devs.iter().any(|d| d == primary_dev) {
            return Some(devs);
        }
    }
    None
}

/// Identify explicitly encryption-capable dm-crypt UUID prefixes (libcryptsetup
/// convention). Integrity-only `CRYPT-` targets such as `CRYPT-VERITY-` and
/// `CRYPT-INTEGRITY-` return `None` so traversal continues into their backing
/// devices rather than misreporting plaintext storage as encrypted.
pub fn classify_dm_encryption_uuid(uuid: &str) -> Option<&'static str> {
    let u = uuid.trim();
    if u.starts_with("CRYPT-LUKS2-") {
        Some("LUKS2")
    } else if u.starts_with("CRYPT-LUKS1-") {
        Some("LUKS1")
    } else if u.starts_with("CRYPT-PLAIN-") {
        Some("dm-crypt-plain")
    } else if u.starts_with("CRYPT-TCRYPT-") {
        Some("TCRYPT")
    } else if u.starts_with("CRYPT-BITLK-") {
        Some("BITLK")
    } else if u.starts_with("CRYPT-LOOPAES-") {
        Some("LOOPAES")
    } else if u.starts_with("CRYPT-FVAULT2-") {
        Some("FVAULT2")
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct BlockNode {
    pub dm_uuid: Option<String>,
    pub slaves: Option<Vec<String>>,
}

fn read_sysfs_block_node(dev_name: &str) -> Option<BlockNode> {
    let block_dir = Path::new("/sys/class/block").join(dev_name);
    if !block_dir.exists() {
        return None;
    }
    let dm_uuid = fs::read_to_string(block_dir.join("dm/uuid"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let slaves_dir = block_dir.join("slaves");
    let slaves = if slaves_dir.is_dir() {
        match fs::read_dir(&slaves_dir) {
            Ok(rd) => {
                let mut list: Vec<String> = rd
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                list.sort();
                Some(list)
            }
            Err(_) => None,
        }
    } else {
        Some(Vec::new())
    };
    Some(BlockNode { dm_uuid, slaves })
}

/// Universally verify that EVERY data-bearing backing branch for `/` terminates
/// at a kernel dm-crypt (`CRYPT-...`) node before reporting full root encryption.
pub fn evaluate_block_encryption<F>(roots: &[String], lookup: F) -> SecurityCheck
where
    F: Fn(&str) -> Option<BlockNode>,
{
    if roots.is_empty() {
        return SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: "No backing block devices identified for /".into(),
        };
    }

    let mut encrypted: Vec<(String, String)> = Vec::new();
    let mut unencrypted: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();

    fn walk<F>(
        dev: &str,
        lookup: &F,
        path_stack: &mut HashSet<String>,
        depth: usize,
        encrypted: &mut Vec<(String, String)>,
        unencrypted: &mut Vec<String>,
        unverified: &mut Vec<String>,
    ) where
        F: Fn(&str) -> Option<BlockNode>,
    {
        if depth > 8 || !path_stack.insert(dev.to_string()) {
            unverified.push(dev.to_string());
            return;
        }
        let Some(node) = lookup(dev) else {
            unverified.push(dev.to_string());
            path_stack.remove(dev);
            return;
        };
        if let Some(uuid) = &node.dm_uuid
            && let Some(kind) = classify_dm_encryption_uuid(uuid)
        {
            if !encrypted.iter().any(|(d, _)| d == dev) {
                encrypted.push((dev.to_string(), kind.to_string()));
            }
            path_stack.remove(dev);
            return;
        }
        match node.slaves {
            None => unverified.push(dev.to_string()),
            Some(slaves) if slaves.is_empty() => {
                if !unencrypted.iter().any(|d| d == dev) {
                    unencrypted.push(dev.to_string());
                }
            }
            Some(slaves) => {
                for slave in slaves {
                    walk(
                        &slave,
                        lookup,
                        path_stack,
                        depth + 1,
                        encrypted,
                        unencrypted,
                        unverified,
                    );
                }
            }
        }
        path_stack.remove(dev);
    }

    let mut stack = HashSet::new();
    for root in roots {
        walk(
            root,
            &lookup,
            &mut stack,
            0,
            &mut encrypted,
            &mut unencrypted,
            &mut unverified,
        );
    }

    if !unencrypted.is_empty() && !encrypted.is_empty() {
        let enc_names: Vec<&str> = encrypted.iter().map(|(d, _)| d.as_str()).collect();
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "fail",
            detail: format!(
                "Mixed root / backing: unencrypted {} alongside dm-crypt ({})",
                unencrypted.join(", "),
                enc_names.join(", ")
            ),
        }
    } else if !unverified.is_empty() {
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: format!(
                "Unable to verify all root / backing branches ({})",
                unverified.join(", ")
            ),
        }
    } else if unencrypted.is_empty() && !encrypted.is_empty() {
        let summary: Vec<String> = encrypted
            .iter()
            .map(|(d, k)| format!("{d}:{k}"))
            .collect();
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "pass",
            detail: format!("Root / fully backed by dm-crypt ({})", summary.join(", ")),
        }
    } else {
        SecurityCheck {
            id: "luks",
            label: "Disk Encryption",
            status: "warn",
            detail: format!("Root / mounted on {} (not backed by dm-crypt)", unencrypted.join(", ")),
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

    #[test]
    fn firewall_distinguishes_running_service_from_verified_policy() {
        // Config present but services stopped -> FAIL
        let inactive = evaluate_firewall_state(
            Some(("inactive".into(), "inactive".into(), "inactive".into())),
            Some(true),
            Some("DROP"),
            true,
        );
        assert_eq!(inactive.status, "fail");

        // Running ufw/firewalld/nftables without root policy audit -> INFO (never false PASS)
        let ufw_running = evaluate_firewall_state(
            Some(("active".into(), "inactive".into(), "inactive".into())),
            Some(true),
            Some("DROP"),
            true,
        );
        assert_eq!(ufw_running.status, "info");

        let fwld_running = evaluate_firewall_state(
            Some(("inactive".into(), "inactive".into(), "active".into())),
            None,
            None,
            false,
        );
        assert_eq!(fwld_running.status, "info");

        // Running UFW with explicit DEFAULT_INPUT_POLICY=ACCEPT -> WARN
        let ufw_accept = evaluate_firewall_state(
            Some(("active".into(), "inactive".into(), "inactive".into())),
            Some(true),
            Some("ACCEPT"),
            true,
        );
        assert_eq!(ufw_accept.status, "warn");

        let no_systemd = evaluate_firewall_state(None, Some(true), Some("DROP"), true);
        assert_eq!(no_systemd.status, "warn");
    }

    #[test]
    fn root_encryption_verifies_every_backing_branch() {
        let mi = "29 1 0:27 /@ / rw,relatime shared:1 - btrfs /dev/mapper/root rw,compress=zstd:3\n\
                  30 29 0:28 /@home /home rw,relatime - btrfs /dev/mapper/root rw\n";
        assert_eq!(
            extract_root_mount_info(mi),
            Some(("btrfs".into(), "0:27".into(), "/dev/mapper/root".into()))
        );
        assert_eq!(
            classify_dm_encryption_uuid("CRYPT-LUKS2-6402632d2ba5443f8ff4043762fb3bcf-root\n"),
            Some("LUKS2")
        );
        assert_eq!(classify_dm_encryption_uuid("CRYPT-PLAIN-swap"), Some("dm-crypt-plain"));
        assert_eq!(classify_dm_encryption_uuid("CRYPT-VERITY-1234-root"), None);
        assert_eq!(classify_dm_encryption_uuid("CRYPT-INTEGRITY-1234-root"), None);
        assert_eq!(classify_dm_encryption_uuid("LVM-abcd1234"), None);

        // Integrity-only dm-verity on plaintext storage MUST NOT pass (continues into slaves)
        let verity_plaintext = evaluate_block_encryption(&["dm-0".into()], |dev| match dev {
            "dm-0" => Some(BlockNode {
                dm_uuid: Some("CRYPT-VERITY-deadbeef-verityroot".into()),
                slaves: Some(vec!["nvme0n1p2".into()]),
            }),
            "nvme0n1p2" => Some(BlockNode {
                dm_uuid: None,
                slaves: Some(vec![]),
            }),
            _ => None,
        });
        assert_eq!(verity_plaintext.status, "warn");
        assert!(verity_plaintext.detail.contains("nvme0n1p2"));

        // Integrity-only dm-integrity on plaintext storage MUST NOT pass
        let integrity_plaintext = evaluate_block_encryption(&["dm-0".into()], |dev| match dev {
            "dm-0" => Some(BlockNode {
                dm_uuid: Some("CRYPT-INTEGRITY-abcd-introot".into()),
                slaves: Some(vec!["sda2".into()]),
            }),
            "sda2" => Some(BlockNode {
                dm_uuid: None,
                slaves: Some(vec![]),
            }),
            _ => None,
        });
        assert_eq!(integrity_plaintext.status, "warn");

        // dm-verity stacked over LUKS2 passes ONLY because its backing device is LUKS2
        let verity_over_luks = evaluate_block_encryption(&["dm-1".into()], |dev| match dev {
            "dm-1" => Some(BlockNode {
                dm_uuid: Some("CRYPT-VERITY-deadbeef-verityroot".into()),
                slaves: Some(vec!["dm-0".into()]),
            }),
            "dm-0" => Some(BlockNode {
                dm_uuid: Some("CRYPT-LUKS2-6402632d-cryptroot".into()),
                slaves: Some(vec!["nvme0n1p2".into()]),
            }),
            _ => None,
        });
        assert_eq!(verity_over_luks.status, "pass");
        assert!(verity_over_luks.detail.contains("dm-0:LUKS2"));

        // Mixed LVM volume: one encrypted slave (dm-0) + one raw slave (nvme1n1p1) -> FAIL!
        let mixed = evaluate_block_encryption(&["dm-2".into()], |dev| match dev {
            "dm-2" => Some(BlockNode {
                dm_uuid: Some("LVM-rootvg-root".into()),
                slaves: Some(vec!["dm-0".into(), "nvme1n1p1".into()]),
            }),
            "dm-0" => Some(BlockNode {
                dm_uuid: Some("CRYPT-LUKS2-aaa-crypt0".into()),
                slaves: Some(vec!["nvme0n1p2".into()]),
            }),
            "nvme1n1p1" => Some(BlockNode {
                dm_uuid: None,
                slaves: Some(vec![]),
            }),
            _ => None,
        });
        assert_eq!(mixed.status, "fail");
        assert!(mixed.detail.contains("nvme1n1p1"));

        // Multi-device Btrfs: dm-0 encrypted + sdb1 raw -> FAIL!
        let mixed_btrfs = evaluate_block_encryption(&["dm-0".into(), "sdb1".into()], |dev| match dev {
            "dm-0" => Some(BlockNode {
                dm_uuid: Some("CRYPT-LUKS2-aaa-crypt0".into()),
                slaves: Some(vec!["nvme0n1p2".into()]),
            }),
            "sdb1" => Some(BlockNode {
                dm_uuid: None,
                slaves: Some(vec![]),
            }),
            _ => None,
        });
        assert_eq!(mixed_btrfs.status, "fail");

        // Fully encrypted multi-branch LVM (both dm-0 & dm-1 are LUKS2) -> PASS!
        let full = evaluate_block_encryption(&["dm-2".into()], |dev| match dev {
            "dm-2" => Some(BlockNode {
                dm_uuid: Some("LVM-rootvg-root".into()),
                slaves: Some(vec!["dm-0".into(), "dm-1".into()]),
            }),
            "dm-0" => Some(BlockNode {
                dm_uuid: Some("CRYPT-LUKS2-aaa-crypt0".into()),
                slaves: Some(vec!["nvme0n1p2".into()]),
            }),
            "dm-1" => Some(BlockNode {
                dm_uuid: Some("CRYPT-LUKS2-bbb-crypt1".into()),
                slaves: Some(vec!["nvme1n1p1".into()]),
            }),
            _ => None,
        });
        assert_eq!(full.status, "pass");
        assert!(full.detail.contains("dm-0:LUKS2"));
        assert!(full.detail.contains("dm-1:LUKS2"));
    }
}
