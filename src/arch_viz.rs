//! Live Arch Linux & Omarchy internal architecture inspector.
//! Reads hardware, storage pipeline, kernel, cgroup v2, Wayland/Hyprland,
//! pacman local DB, and top RAM workloads strictly from /proc, /sys, and IPC.
//! Zero root required, zero external crates, zero pacman spawns.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::json::{Json, Value, parse_json};

#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub name: String,
    pub mode: String,
    pub focused: bool,
}

#[derive(Debug, Clone)]
pub struct TopProcess {
    pub pid: u32,
    pub comm: String,
    pub mem_mb: f64,
}

#[derive(Debug, Clone)]
pub struct ArchState {
    // Layer 1: Silicon & Storage
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_governor: String,
    pub gpu_driver: String,
    pub gpu_pci: String,
    pub storage_chain: String,
    pub btrfs_subvols: Vec<String>,
    pub swap_summary: String,
    // Layer 2: Kernel
    pub kernel_release: String,
    pub kernel_preempt: String,
    pub uptime_sec: u64,
    pub modules_count: usize,
    pub installed_kernels: Vec<String>,
    pub active_lsms: String,
    pub tainted: bool,
    // Layer 3: Init & Cgroup v2
    pub init_comm: String,
    pub cgroup_mode: String,
    pub cgroup_controllers: String,
    pub process_count: usize,
    // Layer 4: Wayland & Omarchy Session
    pub wayland_display: String,
    pub compositor: String,
    pub compositor_mem_mb: f64,
    pub shell_mem_mb: f64,
    pub audio_engine: String,
    pub displays: Vec<DisplayInfo>,
    // Layer 6: Arch Ecosystem & Top Workloads
    pub pacman_pkg_count: usize,
    pub last_pacman_sync: String,
    pub top_procs: Vec<TopProcess>,
}

impl ArchState {
    pub fn collect() -> Self {
        let (cpu_model, cpu_cores) = read_cpu_info();
        let cpu_governor = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let (gpu_driver, gpu_pci) = read_gpu_info();
        let (storage_chain, btrfs_subvols) = read_storage_pipeline();
        let swap_summary = read_swap_summary();

        let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        let version_str = fs::read_to_string("/proc/version").unwrap_or_default();
        let kernel_preempt = parse_preempt_mode(&version_str);
        let uptime_sec = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .map(|f| f as u64)
            .unwrap_or(0);
        let modules_count = fs::read_to_string("/proc/modules")
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        let installed_kernels = read_installed_kernels();
        let active_lsms = fs::read_to_string("/sys/kernel/security/lsm")
            .unwrap_or_default()
            .trim()
            .to_string();
        let tainted = fs::read_to_string("/proc/sys/kernel/tainted")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|v| v != 0)
            .unwrap_or(false);

        let init_comm = fs::read_to_string("/proc/1/comm")
            .unwrap_or_else(|_| "systemd".into())
            .trim()
            .to_string();
        let cgroup_controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
            .unwrap_or_default()
            .trim()
            .to_string();
        let cgroup_mode = if !cgroup_controllers.is_empty() {
            "cgroup v2 unified".to_string()
        } else {
            "cgroup".to_string()
        };

        let (process_count, compositor, compositor_mem_mb, shell_mem_mb, audio_engine, top_procs) =
            scan_os_processes();

        let wayland_display = env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-1".into());
        let displays = query_hyprland_displays();

        let pacman_pkg_count = count_pacman_packages();
        let last_pacman_sync = read_last_pacman_timestamp();

        Self {
            cpu_model,
            cpu_cores,
            cpu_governor,
            gpu_driver,
            gpu_pci,
            storage_chain,
            btrfs_subvols,
            swap_summary,
            kernel_release,
            kernel_preempt,
            uptime_sec,
            modules_count,
            installed_kernels,
            active_lsms,
            tainted,
            init_comm,
            cgroup_mode,
            cgroup_controllers,
            process_count,
            wayland_display,
            compositor,
            compositor_mem_mb,
            shell_mem_mb,
            audio_engine,
            displays,
            pacman_pkg_count,
            last_pacman_sync,
            top_procs,
        }
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("cpuModel", Json::s(self.cpu_model.clone())),
            ("cpuCores", Json::Uint(self.cpu_cores as u64)),
            ("cpuGovernor", Json::s(self.cpu_governor.clone())),
            ("gpuDriver", Json::s(self.gpu_driver.clone())),
            ("gpuPci", Json::s(self.gpu_pci.clone())),
            ("storageChain", Json::s(self.storage_chain.clone())),
            (
                "btrfsSubvols",
                Json::Array(self.btrfs_subvols.iter().map(|s| Json::s(s.clone())).collect()),
            ),
            ("swapSummary", Json::s(self.swap_summary.clone())),
            ("kernelRelease", Json::s(self.kernel_release.clone())),
            ("kernelPreempt", Json::s(self.kernel_preempt.clone())),
            ("uptimeSec", Json::Uint(self.uptime_sec)),
            ("modulesCount", Json::Uint(self.modules_count as u64)),
            (
                "installedKernels",
                Json::Array(self.installed_kernels.iter().map(|k| Json::s(k.clone())).collect()),
            ),
            ("activeLsms", Json::s(self.active_lsms.clone())),
            ("tainted", Json::Bool(self.tainted)),
            ("initComm", Json::s(self.init_comm.clone())),
            ("cgroupMode", Json::s(self.cgroup_mode.clone())),
            ("cgroupControllers", Json::s(self.cgroup_controllers.clone())),
            ("processCount", Json::Uint(self.process_count as u64)),
            ("waylandDisplay", Json::s(self.wayland_display.clone())),
            ("compositor", Json::s(self.compositor.clone())),
            ("compositorMemMb", Json::Float(self.compositor_mem_mb)),
            ("shellMemMb", Json::Float(self.shell_mem_mb)),
            ("audioEngine", Json::s(self.audio_engine.clone())),
            (
                "displays",
                Json::Array(
                    self.displays
                        .iter()
                        .map(|d| {
                            Json::Object(vec![
                                ("name", Json::s(d.name.clone())),
                                ("mode", Json::s(d.mode.clone())),
                                ("focused", Json::Bool(d.focused)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("pacmanPkgCount", Json::Uint(self.pacman_pkg_count as u64)),
            ("lastPacmanSync", Json::s(self.last_pacman_sync.clone())),
            (
                "topProcs",
                Json::Array(
                    self.top_procs
                        .iter()
                        .map(|p| {
                            Json::Object(vec![
                                ("pid", Json::Uint(p.pid as u64)),
                                ("comm", Json::s(p.comm.clone())),
                                ("memMb", Json::Float(p.mem_mb)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

fn read_cpu_info() -> (String, usize) {
    let raw = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut model = String::new();
    let mut cores = 0usize;
    for line in raw.lines() {
        if line.starts_with("processor") {
            cores += 1;
        } else if model.is_empty()
            && line.starts_with("model name")
            && let Some((_, val)) = line.split_once(':')
        {
            model = compact_cpu_name(val.trim());
        }
    }
    if model.is_empty() {
        model = "Linux CPU".into();
    }
    (model, cores.max(1))
}

pub fn compact_cpu_name(raw: &str) -> String {
    raw.replace("(R)", "")
        .replace("(TM)", "")
        .replace("12th Gen ", "")
        .replace("13th Gen ", "")
        .replace("14th Gen ", "")
        .replace("CPU ", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_gpu_info() -> (String, String) {
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
        return ("unknown".into(), String::new());
    };
    let mut cards: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
        .filter(|n| n.starts_with("card") && !n.contains('-'))
        .collect();
    cards.sort();

    for card in cards {
        let uevent_path = format!("/sys/class/drm/{card}/device/uevent");
        if let Ok(raw) = fs::read_to_string(uevent_path) {
            let mut driver = String::new();
            let mut pci = String::new();
            for line in raw.lines() {
                if let Some(v) = line.strip_prefix("DRIVER=") {
                    driver = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("PCI_ID=") {
                    pci = v.trim().to_string();
                }
            }
            if !driver.is_empty() {
                return (driver, pci);
            }
        }
    }
    ("kms".into(), String::new())
}

fn read_storage_pipeline() -> (String, Vec<String>) {
    let mut phys_disk = String::new();
    if let Ok(blocks) = fs::read_dir("/sys/block") {
        let mut names: Vec<String> = blocks
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
            .filter(|n| n.starts_with("nvme") || n.starts_with("sd") || n.starts_with("vd"))
            .collect();
        names.sort();
        if let Some(first) = names.first() {
            phys_disk = first.clone();
        }
    }

    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let has_luks = cmdline.contains("cryptdevice=")
        || cmdline.contains("rd.luks")
        || Path::new("/dev/mapper/root").exists();

    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let (fs_type, compress, subvols) = parse_mounts_storage(&mounts);

    let mut chain = Vec::new();
    if !phys_disk.is_empty() {
        chain.push(phys_disk);
    }
    if has_luks {
        chain.push("LUKS dm-crypt".into());
    }
    let fs_label = match (fs_type.is_empty(), compress.is_empty()) {
        (false, false) => format!("{fs_type} ({compress})"),
        (false, true) => fs_type,
        _ => "root".into(),
    };
    chain.push(fs_label);
    if Path::new("/sys/block/zram0").exists() {
        chain.push("zram0".into());
    }

    (chain.join(" → "), subvols)
}

pub fn parse_mounts_storage(mounts: &str) -> (String, String, Vec<String>) {
    let mut fs_type = String::new();
    let mut compress = String::new();
    let mut subvols: Vec<String> = Vec::new();

    for line in mounts.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let dev = cols[0];
        let mnt = cols[1];
        let fst = cols[2];
        let opts = cols[3];

        if fst == "btrfs" || (mnt == "/" && fst != "tmpfs" && fst != "overlay") {
            if fs_type.is_empty() {
                fs_type = fst.to_string();
            }
            for opt in opts.split(',') {
                if compress.is_empty() && opt.starts_with("compress=") {
                    compress = opt.trim_start_matches("compress=").to_string();
                }
                if let Some(sv) = opt.strip_prefix("subvol=") {
                    let s = sv.to_string();
                    if !subvols.contains(&s) && subvols.len() < 8 {
                        subvols.push(s);
                    }
                }
            }
        }
        let _ = dev;
    }
    subvols.sort();
    (fs_type, compress, subvols)
}

fn read_swap_summary() -> String {
    let raw = fs::read_to_string("/proc/swaps").unwrap_or_default();
    let mut parts = Vec::new();
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let name = Path::new(cols[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(cols[0]);
        let size_kb = cols[2].parse::<u64>().unwrap_or(0);
        let used_kb = cols[3].parse::<u64>().unwrap_or(0);
        let size_gb = size_kb as f64 / (1024.0 * 1024.0);
        let used_mb = used_kb as f64 / 1024.0;
        parts.push(format!("{name} {:.0}G ({:.0}M used)", size_gb, used_mb));
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(" · ")
    }
}

pub fn parse_preempt_mode(version: &str) -> String {
    for tok in version.split_whitespace() {
        if tok.starts_with("PREEMPT") {
            return tok.to_string();
        }
    }
    "SMP".into()
}

fn read_installed_kernels() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/usr/lib/modules") else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
        .filter(|s| !s.starts_with('.'))
        .collect();
    out.sort();
    out
}

fn scan_os_processes() -> (usize, String, f64, f64, String, Vec<TopProcess>) {
    let Ok(entries) = fs::read_dir("/proc") else {
        return (0, "Wayland".into(), 0.0, 0.0, "PipeWire".into(), Vec::new());
    };

    let mut proc_count = 0usize;
    let mut compositor = String::new();
    let mut compositor_mem = 0.0f64;
    let mut shell_mem = 0.0f64;
    let mut audio = String::new();
    let mut top: Vec<TopProcess> = Vec::new();

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(name_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        proc_count += 1;

        let pdir = entry.path();
        let Ok(status) = fs::read_to_string(pdir.join("status")) else {
            continue;
        };
        let mut comm = String::new();
        let mut rss_kb: u64 = 0;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Name:") {
                comm = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0);
                break;
            }
        }
        if comm.is_empty() {
            continue;
        }
        let mem_mb = rss_kb as f64 / 1024.0;
        let lower = comm.to_ascii_lowercase();

        if lower == "hyprland" || lower == "sway" || lower == "niri" {
            compositor = comm.clone();
            compositor_mem = mem_mb;
        } else if lower.contains("quickshell") || lower == "omarchy-shell" {
            shell_mem += mem_mb;
        } else if audio.is_empty() && (lower == "pipewire" || lower == "pulseaudio") {
            audio = if lower == "pipewire" { "PipeWire".into() } else { "PulseAudio".into() };
        }

        if mem_mb >= 32.0 {
            top.push(TopProcess { pid, comm, mem_mb });
        }
    }

    top.sort_by(|a, b| b.mem_mb.total_cmp(&a.mem_mb));
    top.truncate(6);

    if compositor.is_empty() {
        compositor = "Hyprland".into();
    }
    if audio.is_empty() {
        audio = "PipeWire".into();
    }

    (proc_count, compositor, compositor_mem, shell_mem, audio, top)
}

fn query_hyprland_displays() -> Vec<DisplayInfo> {
    let Ok(sig) = env::var("HYPRLAND_INSTANCE_SIGNATURE") else {
        return Vec::new();
    };
    let Ok(runtime) = env::var("XDG_RUNTIME_DIR") else {
        return Vec::new();
    };
    let sock_path = format!("{runtime}/hypr/{sig}/.socket.sock");
    let Ok(mut stream) = UnixStream::connect(&sock_path) else {
        return Vec::new();
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(400)));
    if stream.write_all(b"j/monitors").is_err() {
        return Vec::new();
    }
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    parse_hyprland_monitors(&raw)
}

pub fn parse_hyprland_monitors(raw: &str) -> Vec<DisplayInfo> {
    let Ok(parsed) = parse_json(raw) else {
        return Vec::new();
    };
    let Some(arr) = parsed.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for m in arr {
        let name = m.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let w = m.get("width").and_then(Value::as_u64).unwrap_or(0);
        let h = m.get("height").and_then(Value::as_u64).unwrap_or(0);
        let hz = match m.get("refreshRate") {
            Some(Value::Num(f)) => f.round() as u64,
            _ => 60,
        };
        let focused = m.get("focused").and_then(Value::as_bool).unwrap_or(false);
        out.push(DisplayInfo {
            name,
            mode: format!("{w}x{h}@{hz}Hz"),
            focused,
        });
    }
    out
}

fn count_pacman_packages() -> usize {
    let Ok(entries) = fs::read_dir("/var/lib/pacman/local") else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            n != "ALPM_DB_VERSION" && e.path().is_dir()
        })
        .count()
}

fn read_last_pacman_timestamp() -> String {
    let Ok(raw) = fs::read_to_string("/var/log/pacman.log") else {
        return String::new();
    };
    parse_last_pacman_sync(&raw)
}

pub fn parse_last_pacman_sync(raw: &str) -> String {
    for line in raw.lines().rev() {
        if line.contains("[ALPM] upgraded ") || line.contains("[ALPM] installed ") {
            if let Some(rest) = line.strip_prefix('[')
                && let Some((ts, _)) = rest.split_once(']')
            {
                // Format `2026-11-16T15:45:10+0545` -> `2026-11-16 15:45`
                let clean = ts.replace('T', " ");
                return clean.chars().take(16).collect();
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_btrfs_subvols_and_compression() {
        let mounts = "/dev/mapper/root / btrfs rw,relatime,compress=zstd:3,ssd,subvol=/@ 0 0\n\
                      /dev/mapper/root /home btrfs rw,relatime,compress=zstd:3,subvol=/@home 0 0\n";
        let (fst, comp, subs) = parse_mounts_storage(mounts);
        assert_eq!(fst, "btrfs");
        assert_eq!(comp, "zstd:3");
        assert_eq!(subs, vec!["/@", "/@home"]);
    }

    #[test]
    fn parses_hyprland_monitors_json() {
        let raw = r#"[{"name":"HDMI-A-1","width":1920,"height":1080,"refreshRate":60.0,"focused":true},{"name":"eDP-1","width":1920,"height":1200,"refreshRate":60.002,"focused":false}]"#;
        let list = parse_hyprland_monitors(raw);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "HDMI-A-1");
        assert_eq!(list[0].mode, "1920x1080@60Hz");
        assert!(list[0].focused);
    }

    #[test]
    fn parses_last_pacman_log_timestamp() {
        let log = "[2026-11-15T10:00:00+0545] [PACMAN] Running 'pacman -Syu'\n\
                   [2026-11-16T15:45:10+0545] [ALPM] upgraded linux-omarchy (7.2.11 -> 7.2.15)\n";
        assert_eq!(parse_last_pacman_sync(log), "2026-11-16 15:45");
    }
}
