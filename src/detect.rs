//! Framework/stack classification, git branch reading, and SSH / K8s tunnel parsing.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackInfo {
    pub framework: String,
    pub category: &'static str, // "web" | "data" | "tunnel" | "system"
    pub is_http: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelInfo {
    pub pid: u32,
    pub kind: &'static str, // "ssh" | "k8s"
    pub direction: String,  // "L" | "R" | "D" | "PF"
    pub local_port: u16,
    pub target: String,
    pub via: String,
    pub owned: bool,
}

pub fn classify_process(comm: &str, cmdline: &str, cwd: &str, port: u16, uid: u32, my_uid: u32) -> StackInfo {
    let lower_comm = comm.to_ascii_lowercase();
    let lower_cmd = cmdline.to_ascii_lowercase();
    let lower_cwd = cwd.to_ascii_lowercase();

    // Tunnels
    if lower_comm == "ssh" || (lower_cmd.contains("kubectl") && lower_cmd.contains("port-forward")) {
        return StackInfo {
            framework: if lower_comm == "ssh" {
                "SSH Tunnel".to_string()
            } else {
                "K8s Forward".to_string()
            },
            category: "tunnel",
            is_http: matches!(port, 80 | 443 | 3000..=3999 | 4000..=4999 | 5000..=5999 | 8000..=8999 | 9000..=9099),
        };
    }

    // Build daemons, IDE internal servers, AI agent IPC, desktop apps -> "system"
    // (still visible when expanding Background / System drawer so you can spot/kill a 3.5 GB Gradle daemon!)
    if lower_cmd.contains("org.gradle.launcher.daemon") || lower_cwd.contains("/.gradle/daemon") {
        return StackInfo { framework: "Gradle Daemon".into(), category: "system", is_http: false };
    }
    if lower_cmd.contains("kotlincompiledaemon") || lower_cwd.contains("/kotlin/daemon") {
        return StackInfo { framework: "Kotlin Daemon".into(), category: "system", is_http: false };
    }
    if lower_comm == "adb" {
        return StackInfo { framework: "Android ADB".into(), category: "system", is_http: false };
    }

    let desktop_and_ide_comms = [
        "studio", "idea", "pycharm", "webstorm", "goland", "rustrover", "clion", "rider",
        "jetbrains-toolb", "code", "cursor", "windsurf", "zed", "spotify", "discord",
        "slack", "telegram-deskto", "steam", "obsidian", "1password", "dropbox", "syncthing",
        "chromium", "chrome", "firefox", "brave", "claude", "agy", "codex", "antigravity",
        "language_server", "rust-analyzer", "gopls", "pylsp", "clangd", "jdtls", "mcp-",
    ];
    if desktop_and_ide_comms.iter().any(|p| lower_comm == *p || lower_comm.starts_with(p)) {
        return StackInfo {
            framework: comm.to_string(),
            category: "system",
            is_http: false,
        };
    }

    // Databases, message brokers, cloud emulators & local AI
    if lower_comm.contains("postgres") || port == 5432 {
        return StackInfo { framework: "PostgreSQL".into(), category: "data", is_http: false };
    }
    if lower_comm.contains("redis") || lower_comm.contains("valkey") || port == 6379 {
        return StackInfo { framework: "Redis".into(), category: "data", is_http: false };
    }
    if lower_comm.contains("mysqld") || lower_comm.contains("mariadbd") || port == 3306 {
        return StackInfo { framework: "MySQL".into(), category: "data", is_http: false };
    }
    if lower_comm.contains("mongod") || port == 27017 {
        return StackInfo { framework: "MongoDB".into(), category: "data", is_http: false };
    }
    if lower_cmd.contains("kafka") || port == 9092 || port == 29092 {
        return StackInfo { framework: "Kafka".into(), category: "data", is_http: false };
    }
    if lower_cmd.contains("localstack") || lower_cmd.contains("floci") || port == 4566 {
        return StackInfo { framework: "LocalStack".into(), category: "data", is_http: true };
    }
    if lower_comm.contains("ollama") || port == 11434 {
        return StackInfo { framework: "Ollama AI".into(), category: "data", is_http: true };
    }
    if lower_comm.contains("clickhouse") || port == 8123 || (port == 9000 && lower_cmd.contains("clickhouse")) {
        return StackInfo { framework: "ClickHouse".into(), category: "data", is_http: port == 8123 };
    }
    if lower_comm.contains("minio") || (port == 9000 && lower_cmd.contains("minio")) || (port == 9001 && lower_cmd.contains("minio")) {
        return StackInfo { framework: "MinIO".into(), category: "data", is_http: true };
    }
    if lower_cmd.contains("elasticsearch") || lower_cmd.contains("opensearch") || port == 9200 {
        return StackInfo { framework: "Elastic".into(), category: "data", is_http: true };
    }
    if lower_cmd.contains("rabbitmq") || port == 5672 || port == 15672 {
        return StackInfo { framework: "RabbitMQ".into(), category: "data", is_http: port == 15672 };
    }

    // System daemons
    let system_comms = [
        "systemd-resolve", "systemd-network", "sshd", "cupsd", "avahi-daemon",
        "dnsmasq", "dhclient", "tailscaled", "kdeconnectd", "wayvnc", "pulseaudio",
        "pipewire", "dbus-daemon", "rpcbind", "chronyd", "ntpd", "containerd",
    ];
    if system_comms.iter().any(|s| lower_comm.starts_with(s)) || (uid == 0 && !lower_comm.contains("docker") && !lower_comm.contains("nginx") && !lower_comm.contains("caddy") && !lower_comm.contains("httpd")) {
        return StackInfo {
            framework: comm.to_string(),
            category: "system",
            is_http: false,
        };
    }

    // Specific Web / Dev frameworks from cmdline
    let mut recognized_dev = true;
    let framework = if lower_cmd.contains("next-server") || lower_cmd.contains("next dev") || lower_cmd.contains("/.bin/next") {
        "Next.js"
    } else if lower_cmd.contains("vite") {
        "Vite"
    } else if lower_cmd.contains("astro") {
        "Astro"
    } else if lower_cmd.contains("nuxt") {
        "Nuxt"
    } else if lower_cmd.contains("svelte") {
        "SvelteKit"
    } else if lower_cmd.contains("storybook") {
        "Storybook"
    } else if lower_cmd.contains("remix") || lower_cmd.contains("react-router") {
        "Remix"
    } else if lower_cmd.contains("webpack") || lower_cmd.contains("react-scripts") {
        "React"
    } else if lower_cmd.contains("uvicorn") || lower_cmd.contains("fastapi") {
        "FastAPI"
    } else if lower_cmd.contains("manage.py") || lower_cmd.contains("django") {
        "Django"
    } else if lower_cmd.contains("flask") || lower_cmd.contains("gunicorn") {
        "Flask"
    } else if lower_cmd.contains("rails") || lower_cmd.contains("puma") {
        "Rails"
    } else if lower_cmd.contains("spring") || lower_cmd.contains("bootrun") || lower_cmd.contains("tomcat") || lower_cmd.contains("jetty") {
        "Spring / Java"
    } else if lower_cmd.contains("quarkus") {
        "Quarkus"
    } else if lower_cmd.contains("artisan") || lower_comm.starts_with("php") {
        "PHP / Laravel"
    } else if lower_comm == "bun" {
        "Bun"
    } else if lower_comm == "deno" {
        "Deno"
    } else if lower_comm == "node" || lower_comm == "nodejs" {
        "Node.js"
    } else if lower_comm.starts_with("python") {
        "Python"
    } else if lower_comm == "java" {
        if port >= 32768 {
            recognized_dev = false;
            "Java IPC"
        } else {
            "Java"
        }
    } else if lower_comm == "ruby" {
        "Ruby"
    } else if lower_comm == "nginx" {
        "Nginx"
    } else if lower_comm == "caddy" {
        "Caddy"
    } else if lower_comm.contains("docker-proxy") || lower_comm.contains("rootlessport") {
        "Docker"
    } else if lower_cmd.contains("target/debug") || lower_cmd.contains("target/release") || lower_comm == "cargo" {
        "Rust"
    } else if lower_cmd.contains("go-build") || lower_comm == "air" {
        "Go"
    } else {
        recognized_dev = false;
        comm
    };

    // High ephemeral ports (>=32768) from unrecognized binaries are almost always desktop/IDE IPC sockets.
    let is_ephemeral_ipc = port >= 32768 && !recognized_dev;
    let category = if is_ephemeral_ipc {
        "system"
    } else if uid == my_uid || matches!(framework, "Docker" | "Nginx" | "Caddy") {
        "web"
    } else {
        "system"
    };

    let is_http = category == "web"
        && !matches!(port, 22 | 53 | 5432 | 3306 | 6379 | 27017 | 5672 | 9092);

    StackInfo {
        framework: framework.to_string(),
        category,
        is_http,
    }
}

/// Resolve project folder name & git branch from a process's working directory.
pub fn resolve_project_and_branch(cwd: &str, home: &str) -> (String, String) {
    if cwd.is_empty() || cwd == "/" || cwd == home {
        return (String::new(), String::new());
    }
    let path = Path::new(cwd);
    let project = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    let branch = read_git_branch(path);
    (project, branch)
}

/// Walk up at most 4 parent directories looking for `.git/HEAD` without spawning git.
pub fn read_git_branch(start: &Path) -> String {
    let mut cur: Option<PathBuf> = Some(start.to_path_buf());
    for _ in 0..5 {
        let Some(dir) = cur else { break };
        let dot_git = dir.join(".git");
        let head_path = if dot_git.is_dir() {
            Some(dot_git.join("HEAD"))
        } else if dot_git.is_file() {
            // Worktree or submodule: `.git` contains `gitdir: <path>`
            fs::read_to_string(&dot_git)
                .ok()
                .and_then(|s| s.trim().strip_prefix("gitdir:").map(|p| p.trim().to_string()))
                .map(|p| {
                    let pb = PathBuf::from(p);
                    if pb.is_absolute() {
                        pb.join("HEAD")
                    } else {
                        dir.join(pb).join("HEAD")
                    }
                })
        } else {
            None
        };

        if let Some(hp) = head_path
            && let Ok(content) = fs::read_to_string(hp)
        {
            return parse_git_head(&content);
        }
        cur = dir.parent().map(|p| p.to_path_buf());
    }
    String::new()
}

pub fn parse_git_head(content: &str) -> String {
    let trimmed = content.trim();
    if let Some(branch) = trimmed.strip_prefix("ref: refs/heads/") {
        return branch.to_string();
    }
    if let Some(rest) = trimmed.strip_prefix("ref: ") {
        return rest.rsplit('/').next().unwrap_or(rest).to_string();
    }
    // Detached HEAD commit hash
    if trimmed.len() >= 7 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return format!("@{}", &trimmed[..7]);
    }
    String::new()
}

/// Parse `ssh` (`-L`, `-R`, `-D`) and `kubectl port-forward` tunnels from argv.
pub fn parse_tunnels_from_argv(pid: u32, argv: &[String], owned: bool) -> Vec<TunnelInfo> {
    if argv.is_empty() {
        return Vec::new();
    }
    let bin = Path::new(&argv[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&argv[0]);

    if bin == "ssh" {
        return parse_ssh_tunnels(pid, argv, owned);
    }
    if bin == "kubectl" || bin == "k" {
        return parse_kubectl_tunnels(pid, argv, owned);
    }
    Vec::new()
}

fn parse_ssh_tunnels(pid: u32, argv: &[String], owned: bool) -> Vec<TunnelInfo> {
    let mut forwards: Vec<(&str, String)> = Vec::new();
    let mut host = String::new();
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        if (arg == "-L" || arg == "-R" || arg == "-D") && i + 1 < argv.len() {
            let dir = match arg.as_str() {
                "-L" => "L",
                "-R" => "R",
                _ => "D",
            };
            forwards.push((dir, argv[i + 1].clone()));
            i += 2;
            continue;
        }
        if let Some(spec) = arg.strip_prefix("-L") && !spec.is_empty() {
            forwards.push(("L", spec.to_string()));
            i += 1;
            continue;
        }
        if let Some(spec) = arg.strip_prefix("-R") && !spec.is_empty() {
            forwards.push(("R", spec.to_string()));
            i += 1;
            continue;
        }
        if let Some(spec) = arg.strip_prefix("-D") && !spec.is_empty() {
            forwards.push(("D", spec.to_string()));
            i += 1;
            continue;
        }
        // Skip flags that consume a value
        if matches!(
            arg.as_str(),
            "-i" | "-p" | "-o" | "-F" | "-J" | "-l" | "-W" | "-b" | "-c" | "-e" | "-m"
        ) {
            i += 2;
            continue;
        }
        if !arg.starts_with('-') && host.is_empty() {
            host = arg.clone();
        }
        i += 1;
    }

    let mut out = Vec::new();
    for (dir, spec) in forwards {
        if dir == "D" {
            let port_str = spec.rsplit(':').next().unwrap_or(&spec);
            if let Ok(local_port) = port_str.parse::<u16>() {
                out.push(TunnelInfo {
                    pid,
                    kind: "ssh",
                    direction: "SOCKS".into(),
                    local_port,
                    target: "SOCKS5 Proxy".into(),
                    via: host.clone(),
                    owned,
                });
            }
            continue;
        }
        // Spec formats: local_port:target_host:target_port OR bind:local_port:target_host:target_port
        let parts: Vec<&str> = spec.split(':').collect();
        let (local_str, target) = match parts.len() {
            3 => (parts[0], format!("{}:{}", parts[1], parts[2])),
            4 => (parts[1], format!("{}:{}", parts[2], parts[3])),
            _ => continue,
        };
        if let Ok(local_port) = local_str.parse::<u16>() {
            out.push(TunnelInfo {
                pid,
                kind: "ssh",
                direction: dir.into(),
                local_port,
                target,
                via: host.clone(),
                owned,
            });
        }
    }
    out
}

fn parse_kubectl_tunnels(pid: u32, argv: &[String], owned: bool) -> Vec<TunnelInfo> {
    let Some(pf_idx) = argv.iter().position(|a| a == "port-forward") else {
        return Vec::new();
    };
    let mut ns = String::new();
    let mut ctx = String::new();
    let mut resource = String::new();
    let mut mappings: Vec<(u16, String)> = Vec::new();

    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        if (arg == "-n" || arg == "--namespace") && i + 1 < argv.len() {
            ns = argv[i + 1].clone();
            i += 2;
            continue;
        }
        if let Some(v) = arg.strip_prefix("--namespace=") {
            ns = v.to_string();
            i += 1;
            continue;
        }
        if arg == "--context" && i + 1 < argv.len() {
            ctx = argv[i + 1].clone();
            i += 2;
            continue;
        }
        if let Some(v) = arg.strip_prefix("--context=") {
            ctx = v.to_string();
            i += 1;
            continue;
        }
        if i > pf_idx && !arg.starts_with('-') {
            if resource.is_empty() {
                resource = arg.clone();
            } else if let Some((lp, rp)) = arg.split_once(':') {
                if let Ok(local_port) = lp.parse::<u16>() {
                    mappings.push((local_port, rp.to_string()));
                }
            } else if let Ok(p) = arg.parse::<u16>() {
                mappings.push((p, p.to_string()));
            }
        }
        i += 1;
    }

    let via = match (ctx.is_empty(), ns.is_empty()) {
        (false, false) => format!("{ctx}/{ns}"),
        (false, true) => ctx,
        (true, false) => ns,
        (true, true) => "k8s".into(),
    };

    mappings
        .into_iter()
        .map(|(local_port, rp)| TunnelInfo {
            pid,
            kind: "k8s",
            direction: "K8s".into(),
            local_port,
            target: format!("{resource}:{rp}"),
            via: via.clone(),
            owned,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_head_branches_and_detached() {
        assert_eq!(parse_git_head("ref: refs/heads/feat/billing\n"), "feat/billing");
        assert_eq!(
            parse_git_head("e08862f9ee92bd1161bab31df81dcfa6f8802918\n"),
            "@e08862f"
        );
    }

    #[test]
    fn detects_frameworks_and_databases() {
        let next = classify_process("node", "node /app/node_modules/.bin/next dev -p 3000", "/home/u/saas", 3000, 1000, 1000);
        assert_eq!(next.framework, "Next.js");
        assert_eq!(next.category, "web");
        assert!(next.is_http);

        let kafka = classify_process("java", "java -cp kafka.jar kafka.Kafka", "/opt/kafka", 9092, 1000, 1000);
        assert_eq!(kafka.framework, "Kafka");
        assert_eq!(kafka.category, "data");
        assert!(!kafka.is_http);

        let pg = classify_process("postgres", "/usr/bin/postgres -D /var/lib/postgres", "/", 5432, 999, 1000);
        assert_eq!(pg.framework, "PostgreSQL");
        assert_eq!(pg.category, "data");

        let gradle = classify_process("java", "java -cp gradle.jar org.gradle.launcher.daemon.bootstrap.GradleDaemon", "/home/u/.gradle/daemon/8.10", 44259, 1000, 1000);
        assert_eq!(gradle.framework, "Gradle Daemon");
        assert_eq!(gradle.category, "system");
        assert!(!gradle.is_http);

        let spotify = classify_process("spotify", "/usr/bin/spotify", "/home/u", 57621, 1000, 1000);
        assert_eq!(spotify.category, "system");

        let agent = classify_process("claude", "claude", "/home/u", 41277, 1000, 1000);
        assert_eq!(agent.category, "system");
    }

    #[test]
    fn parses_ssh_and_kubectl_tunnels() {
        let ssh_argv: Vec<String> = ["ssh", "-N", "-L", "5433:rds.internal:5432", "-D", "1080", "ops@bastion"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let tunnels = parse_tunnels_from_argv(1234, &ssh_argv, true);
        assert_eq!(tunnels.len(), 2);
        assert_eq!(tunnels[0].local_port, 5433);
        assert_eq!(tunnels[0].target, "rds.internal:5432");
        assert_eq!(tunnels[0].via, "ops@bastion");
        assert_eq!(tunnels[1].direction, "SOCKS");
        assert_eq!(tunnels[1].local_port, 1080);

        let k8s_argv: Vec<String> = ["kubectl", "-n", "staging", "port-forward", "svc/api", "8080:80"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let kt = parse_tunnels_from_argv(5678, &k8s_argv, true);
        assert_eq!(kt.len(), 1);
        assert_eq!(kt[0].local_port, 8080);
        assert_eq!(kt[0].target, "svc/api:80");
        assert_eq!(kt[0].via, "staging");
    }
}
