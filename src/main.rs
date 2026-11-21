//! DevDock — Blazing-fast Rust backend & CLI for Omarchy Dev & DevOps Control Center.

mod actions;
mod arch_viz;
mod detect;
mod docker;
mod docker_sock;
mod host;
mod json;
mod kube;
mod proc_ports;
mod security;
mod systemd;
mod traffic;

use std::collections::HashSet;
use std::env;
use std::process::ExitCode;
use std::thread;

use crate::arch_viz::ArchState;
use crate::docker::ContainersState;
use crate::host::HostVitals;
use crate::json::Json;
use crate::kube::KubeState;
use crate::proc_ports::{scan_ports_and_tunnels, tunnel_to_json};
use crate::security::SecurityState;
use crate::systemd::ServicesState;
use crate::traffic::TrafficState;

fn run_scan() -> String {
    // Run ALL independent OS collectors concurrently.
    let (host, containers, (mut ports, tunnels), kube, services, mut traffic, arch) = thread::scope(|s| {
        let h = s.spawn(HostVitals::collect);
        let c = s.spawn(ContainersState::collect);
        let empty_map = std::collections::HashMap::new();
        let p = s.spawn(move || scan_ports_and_tunnels("", &empty_map));
        let k = s.spawn(KubeState::collect);
        let sv = s.spawn(ServicesState::collect);
        let tr = s.spawn(|| TrafficState::collect(&HashSet::new()));
        let ar = s.spawn(ArchState::collect);
        (
            h.join().unwrap_or_else(|_| HostVitals::collect()),
            c.join().unwrap_or_else(|_| ContainersState::collect()),
            p.join().unwrap_or_default(),
            k.join().unwrap_or_else(|_| KubeState::collect()),
            sv.join().unwrap_or_else(|_| ServicesState::collect()),
            tr.join().unwrap_or_else(|_| TrafficState::collect(&HashSet::new())),
            ar.join().unwrap_or_else(|_| ArchState::collect()),
        )
    });

    // Enrich discovered listening ports with LAN URLs and Docker container names.
    for port in &mut ports {
        if port.exposed_lan && !host.lan_ip.is_empty() && port.lan_url.is_empty() {
            port.lan_url = if port.is_http {
                format!("http://{}:{}", host.lan_ip, port.port)
            } else {
                format!("{}:{}", host.lan_ip, port.port)
            };
        }
        if let Some(ctr_name) = containers.port_map.get(&port.port) {
            port.container_name = ctr_name.clone();
            if port.project.is_empty() {
                port.project = ctr_name.clone();
            }
            if port.category == "system" {
                port.category = "data".into();
            }
        }
    }

    let listening_ports: HashSet<u16> = ports.iter().map(|p| p.port).collect();
    traffic.apply_listening_ports(&listening_ports);
    let security = SecurityState::collect(&ports, &traffic);

    let dev_port_count = ports.iter().filter(|p| p.category != "system").count();
    let web_port_count = ports.iter().filter(|p| p.category == "web").count();

    let payload = Json::Object(vec![
        ("version", Json::Uint(2)),
        (
            "summary",
            Json::Object(vec![
                ("devPorts", Json::Uint(dev_port_count as u64)),
                ("webPorts", Json::Uint(web_port_count as u64)),
                ("tunnels", Json::Uint(tunnels.len() as u64)),
                ("runningContainers", Json::Uint(containers.running_count as u64)),
                ("failedServices", Json::Uint(services.failed_count as u64)),
                ("kubeProd", Json::Bool(kube.current_is_prod)),
                ("kubeContext", Json::s(kube.current_context.clone())),
                ("internetConns", Json::Uint(traffic.internet_conns as u64)),
                ("securityCritical", Json::Uint(security.critical_count as u64)),
                ("securityWarnings", Json::Uint(security.warn_count as u64)),
            ]),
        ),
        ("host", host.to_json()),
        ("ports", Json::Array(ports.iter().map(|p| p.to_json()).collect())),
        ("tunnels", Json::Array(tunnels.iter().map(tunnel_to_json).collect())),
        ("containers", containers.to_json()),
        ("kube", kube.to_json()),
        ("services", services.to_json()),
        ("traffic", traffic.to_json()),
        ("security", security.to_json()),
        ("arch", arch.to_json()),
    ]);

    payload.to_string_compact()
}

fn print_human_status(show_all: bool) {
    let (host, containers, (ports, tunnels), kube, services, mut traffic, arch) = thread::scope(|s| {
        let h = s.spawn(HostVitals::collect);
        let c = s.spawn(ContainersState::collect);
        let empty = std::collections::HashMap::new();
        let p = s.spawn(move || scan_ports_and_tunnels("", &empty));
        let k = s.spawn(KubeState::collect);
        let sv = s.spawn(ServicesState::collect);
        let tr = s.spawn(|| TrafficState::collect(&HashSet::new()));
        let ar = s.spawn(ArchState::collect);
        (
            h.join().unwrap_or_else(|_| HostVitals::collect()),
            c.join().unwrap_or_else(|_| ContainersState::collect()),
            p.join().unwrap_or_default(),
            k.join().unwrap_or_else(|_| KubeState::collect()),
            sv.join().unwrap_or_else(|_| ServicesState::collect()),
            tr.join().unwrap_or_else(|_| TrafficState::collect(&HashSet::new())),
            ar.join().unwrap_or_else(|_| ArchState::collect()),
        )
    });
    let listen_set: HashSet<u16> = ports.iter().map(|p| p.port).collect();
    traffic.apply_listening_ports(&listen_set);
    let security = SecurityState::collect(&ports, &traffic);

    println!(
        "DevDock [{}]  load:{:.2}  ram:{:.1}/{:.1}G ({}%)  disk:{}%  lan:{}",
        host.hostname,
        host.load_1m,
        host.mem_used_gb,
        host.mem_total_gb,
        host.mem_pct,
        host.disk_pct,
        if host.lan_ip.is_empty() { "-" } else { &host.lan_ip }
    );
    println!(
        "Arch: {} ({}c) · {} · {} pkgs · Security: {}/{} PASS · Net: {} internet conns",
        arch.cpu_model,
        arch.cpu_cores,
        arch.kernel_release,
        arch.pacman_pkg_count,
        security.pass_count,
        security.checks.len(),
        traffic.internet_conns
    );

    if kube.available {
        let warn = if kube.current_is_prod { " [PROD!]" } else { "" };
        println!("K8s: {} (ns: {}){}", kube.current_context, kube.current_namespace, warn);
    }

    let dev_ports: Vec<_> = ports.iter().filter(|p| p.category != "system").collect();
    let sys_ports: Vec<_> = ports.iter().filter(|p| p.category == "system").collect();
    println!("\nDev & Data Ports ({}):", dev_ports.len());
    if dev_ports.is_empty() {
        println!("  (none listening right now)");
    } else {
        for p in &dev_ports {
            let proj = if p.project.is_empty() { &p.comm } else { &p.project };
            let branch = if p.git_branch.is_empty() {
                String::new()
            } else {
                format!(" ({})", p.git_branch)
            };
            let scope = if p.exposed_lan { "LAN" } else { "local" };
            println!(
                "  :{:<5} {:<14} {}{}  [{} pid={} {:.0}MB]",
                p.port, p.framework, proj, branch, scope, p.pid, p.mem_mb
            );
        }
    }

    if show_all && !sys_ports.is_empty() {
        println!("\nBackground & System Ports ({}):", sys_ports.len());
        for p in &sys_ports {
            let scope = if p.exposed_lan { "LAN" } else { "local" };
            println!(
                "  :{:<5} {:<16} {}  [{} pid={} {:.0}MB]",
                p.port, p.framework, p.comm, scope, p.pid, p.mem_mb
            );
        }
    } else if !sys_ports.is_empty() {
        println!("  (+{} background/system ports — pass --all to view)", sys_ports.len());
    }

    if !tunnels.is_empty() {
        println!("\nTunnels ({}):", tunnels.len());
        for t in &tunnels {
            println!("  :{} -> {} (via {}, pid={})", t.local_port, t.target, t.via, t.pid);
        }
    }

    if containers.available {
        println!("\nContainers ({} running / {} total):", containers.running_count, containers.items.len());
        for c in &containers.items {
            let stack = if c.compose_project.is_empty() {
                String::new()
            } else {
                format!(" [{}]", c.compose_project)
            };
            println!("  {:<20} {:<24} {} {}{}", c.name, c.image, c.state, c.ports_raw, stack);
        }
    }

    if services.failed_count > 0 {
        println!("\nFailed systemd units ({}):", services.failed_count);
        for f in &services.failed_units {
            println!("  ! {} ({})", f.unit, f.sub_state);
        }
    }
}

fn print_net_status() {
    let empty = std::collections::HashMap::new();
    let (ports, _) = scan_ports_and_tunnels("", &empty);
    let listen_set: HashSet<u16> = ports.iter().map(|p| p.port).collect();
    let traffic = TrafficState::collect(&listen_set);
    let sec = SecurityState::collect(&ports, &traffic);

    println!(
        "OS Security Posture: {}/{} PASS  ({} warn, {} fail)",
        sec.pass_count,
        sec.checks.len(),
        sec.warn_count,
        sec.fail_count
    );
    for c in &sec.checks {
        println!("  [{:<4}] {:<18} {}", c.status.to_uppercase(), c.label, c.detail);
    }
    println!(
        "\nActive Connections ({} internet, {} LAN, {} inbound):",
        traffic.internet_conns, traffic.lan_conns, traffic.inbound_conns
    );
    for g in &traffic.groups {
        println!(
            "  {:<18} pid={:<7} net={:<3} lan={:<3} in={:<2} [{}]",
            g.comm, g.pid, g.internet_count, g.lan_count, g.inbound_count, g.max_risk
        );
    }
}

fn print_arch_status() {
    let a = ArchState::collect();
    println!("1. Silicon & Storage : {} ({}c, {}) · GPU {} [{}]", a.cpu_model, a.cpu_cores, a.cpu_governor, a.gpu_driver, a.gpu_pci);
    println!("   Storage Pipeline  : {}", a.storage_chain);
    println!("   Swap              : {}", a.swap_summary);
    println!("2. Linux Kernel      : {} ({}) · {} modules · LSMs: {}", a.kernel_release, a.kernel_preempt, a.modules_count, a.active_lsms);
    println!("3. Init & Cgroups    : {} (PID 1) · {} · {} processes", a.init_comm, a.cgroup_mode, a.process_count);
    println!("4. Wayland & Omarchy : {} ({:.0}MB) · shell ({:.0}MB) · {}", a.compositor, a.compositor_mem_mb, a.shell_mem_mb, a.audio_engine);
    for d in &a.displays {
        println!("   Display           : {} {}{}", d.name, d.mode, if d.focused { " [focused]" } else { "" });
    }
    println!("5. Arch Ecosystem    : {} packages (last sync: {})", a.pacman_pkg_count, a.last_pacman_sync);
    println!("   Top RAM Workloads :");
    for p in &a.top_procs {
        println!("     {:<18} pid={:<7} {:.0} MB", p.comm, p.pid, p.mem_mb);
    }
}

fn print_usage() {
    eprintln!(
        "Usage: devdock <command> [args...]\n\
         Commands:\n\
           scan                                    Emit full DevOps + OS snapshot as JSON\n\
           status [--all]                          Human-readable terminal overview\n\
           net                                     Live internet connections & OS hardening\n\
           arch                                    Live Arch Linux & Omarchy architecture map\n\
           probe <port>                            HTTP HEAD / TCP latency probe on localhost\n\
           stop <pid> <port>                       Send SIGTERM to owned listening process\n\
           kill <pid> <port>                       Send SIGKILL to owned listening process\n\
           net-stop <pid>                          Send SIGTERM to owned process from Net view\n\
           focus <pid>                             Focus Hyprland window owning <pid>\n\
           open <url>                              Open validated local/LAN URL in browser\n\
           copy <text>                             Copy text to Wayland clipboard\n\
           container <start|stop|restart|logs|exec> <id>\n\
           container-tail <id> [lines]             Direct UNIX-socket container log tail\n\
           stack <start|stop> <compose-project>    Start or stop an entire Compose stack\n\
           k8s-switch <context>                    Switch active kubectl context\n\
           service-logs <unit> [--user]            Follow journalctl logs in terminal\n\
           rdns <ip>                               On-demand reverse DNS lookup\n\
           notify <title> <body>                   Send crash-watchdog desktop notification"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("status");

    let result: Result<String, String> = match cmd {
        "scan" => {
            println!("{}", run_scan());
            return ExitCode::SUCCESS;
        }
        "status" => {
            let show_all = args.iter().any(|a| a == "--all" || a == "-a");
            print_human_status(show_all);
            return ExitCode::SUCCESS;
        }
        "net" => {
            print_net_status();
            return ExitCode::SUCCESS;
        }
        "arch" => {
            print_arch_status();
            return ExitCode::SUCCESS;
        }
        "probe" => {
            if args.len() < 2 {
                Err("usage: devdock probe <port>".into())
            } else {
                match args[1].parse::<u16>() {
                    Ok(port) => actions::probe_port(port),
                    Err(_) => Err("port must be 1..65535".into()),
                }
            }
        }
        "net-stop" => {
            if args.len() < 2 {
                Err("usage: devdock net-stop <pid>".into())
            } else {
                match args[1].parse::<u32>() {
                    Ok(pid) => actions::signal_owned_pid(pid, false),
                    Err(_) => Err("pid must be a positive integer".into()),
                }
            }
        }
        "stack" => {
            if args.len() < 3 {
                Err("usage: devdock stack <start|stop> <compose-project>".into())
            } else {
                actions::compose_stack_action(&args[1], &args[2])
            }
        }
        "notify" => {
            if args.len() < 3 {
                Err("usage: devdock notify <title> <body>".into())
            } else {
                actions::notify_watchdog(&args[1], &args[2])
            }
        }
        "stop" | "kill" => {
            if args.len() < 3 {
                Err(format!("usage: devdock {cmd} <pid> <port>"))
            } else {
                match (args[1].parse::<u32>(), args[2].parse::<u16>()) {
                    (Ok(pid), Ok(port)) => actions::signal_port_pid(pid, port, cmd == "kill"),
                    _ => Err("pid and port must be positive integers".into()),
                }
            }
        }
        "focus" => {
            if args.len() < 2 {
                Err("usage: devdock focus <pid>".into())
            } else {
                match args[1].parse::<u32>() {
                    Ok(pid) => actions::focus_hyprland_window(pid),
                    Err(_) => Err("pid must be a positive integer".into()),
                }
            }
        }
        "open" => {
            if args.len() < 2 {
                Err("usage: devdock open <url>".into())
            } else {
                actions::open_url(&args[1])
            }
        }
        "copy" => {
            if args.len() < 2 {
                Err("usage: devdock copy <text>".into())
            } else {
                actions::copy_text(&args[1])
            }
        }
        "container" => {
            if args.len() < 3 {
                Err("usage: devdock container <start|stop|restart|logs> <id>".into())
            } else {
                actions::container_action(&args[1], &args[2])
            }
        }
        "container-tail" => {
            if args.len() < 2 {
                Err("usage: devdock container-tail <id> [lines]".into())
            } else {
                let tail = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(120);
                actions::container_tail_logs(&args[1], tail)
            }
        }
        "k8s-switch" => {
            if args.len() < 2 {
                Err("usage: devdock k8s-switch <context>".into())
            } else {
                actions::switch_kube_context(&args[1])
            }
        }
        "service-logs" => {
            if args.len() < 2 {
                Err("usage: devdock service-logs <unit> [--user]".into())
            } else {
                let is_user = args.get(2).map(|s| s == "--user").unwrap_or(false);
                actions::view_service_logs(&args[1], is_user)
            }
        }
        "rdns" => {
            if args.len() < 2 {
                Err("usage: devdock rdns <ip>".into())
            } else {
                actions::reverse_dns(&args[1])
            }
        }
        "-h" | "--help" | "help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command: {other}")),
    };

    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("devdock: {err}");
            ExitCode::FAILURE
        }
    }
}
