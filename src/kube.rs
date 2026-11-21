//! Kubeconfig reader + PROD context safety guard + AWS profile inspection.
//! Uses `kubectl config view -o json` when `kubectl` is installed (exact
//! kubectl YAML/JSON/merge semantics, zero network calls) and falls back to a
//! strict native JSON + YAML merger that fails closed (`targetUnknown = true`)
//! whenever any kubeconfig file cannot be safely parsed.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;

use crate::json::{Json, Value, parse_json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeContext {
    pub name: String,
    pub namespace: String,
    pub cluster: String,
    pub is_prod: bool,
}

#[derive(Debug, Clone)]
pub struct KubeState {
    pub available: bool,
    pub target_unknown: bool,
    pub warning_detail: String,
    pub current_context: String,
    pub current_namespace: String,
    pub current_is_prod: bool,
    pub contexts: Vec<KubeContext>,
    pub aws_profile: String,
}

impl KubeState {
    fn unavailable(aws_profile: String) -> Self {
        Self {
            available: false,
            target_unknown: false,
            warning_detail: String::new(),
            current_context: String::new(),
            current_namespace: String::new(),
            current_is_prod: false,
            contexts: Vec::new(),
            aws_profile,
        }
    }

    fn unknown(aws_profile: String, detail: String) -> Self {
        Self {
            available: true,
            target_unknown: true,
            warning_detail: detail,
            current_context: String::new(),
            current_namespace: String::new(),
            current_is_prod: false,
            contexts: Vec::new(),
            aws_profile,
        }
    }

    pub fn collect() -> Self {
        let aws_profile = env::var("AWS_PROFILE")
            .or_else(|_| env::var("AWS_DEFAULT_PROFILE"))
            .unwrap_or_default();

        let paths = resolve_kubeconfig_paths();
        let existing: Vec<PathBuf> = paths.into_iter().filter(|p| p.exists()).collect();
        if existing.is_empty() {
            return Self::unavailable(aws_profile);
        }

        // Primary path: delegate to `kubectl config view -o json` when kubectl
        // is installed so kubeconfig loading matches kubectl's exact YAML,
        // JSON, and multi-file merge semantics with zero network calls.
        match Command::new("kubectl")
            .args(["config", "view", "-o", "json"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let raw = String::from_utf8_lossy(&out.stdout);
                return match parse_kubeconfig_json_doc(&raw) {
                    Ok(doc) => finalize_merged_docs(vec![doc], aws_profile),
                    Err(e) => Self::unknown(
                        aws_profile,
                        format!("kubectl config view returned unparseable JSON: {e}"),
                    ),
                };
            }
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Self::unknown(
                    aws_profile,
                    if err.is_empty() {
                        "kubectl failed to load merged kubeconfig".into()
                    } else {
                        err.chars().take(140).collect()
                    },
                );
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // kubectl is not installed; fall back to strict native JSON+YAML loader.
            }
            Err(e) => {
                return Self::unknown(
                    aws_profile,
                    format!("unable to run kubectl config view: {e}"),
                );
            }
        }

        let mut raw_docs: Vec<String> = Vec::with_capacity(existing.len());
        for path in &existing {
            match fs::read_to_string(path) {
                Ok(raw) => raw_docs.push(raw),
                Err(e) => {
                    return Self::unknown(
                        aws_profile,
                        format!("cannot read kubeconfig {}: {e}", path.display()),
                    );
                }
            }
        }
        let refs: Vec<&str> = raw_docs.iter().map(String::as_str).collect();
        merge_kubeconfigs(&refs, aws_profile)
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("available", Json::Bool(self.available)),
            ("targetUnknown", Json::Bool(self.target_unknown)),
            ("warningDetail", Json::s(self.warning_detail.clone())),
            ("currentContext", Json::s(self.current_context.clone())),
            ("currentNamespace", Json::s(self.current_namespace.clone())),
            ("currentIsProd", Json::Bool(self.current_is_prod)),
            ("awsProfile", Json::s(self.aws_profile.clone())),
            (
                "contexts",
                Json::Array(
                    self.contexts
                        .iter()
                        .map(|c| {
                            Json::Object(vec![
                                ("name", Json::s(c.name.clone())),
                                ("namespace", Json::s(c.namespace.clone())),
                                ("cluster", Json::s(c.cluster.clone())),
                                ("isProd", Json::Bool(c.is_prod)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

pub fn is_prod_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    for seg in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        if matches!(seg, "prod" | "production" | "prd" | "live" | "mainnet") {
            return true;
        }
    }
    false
}

fn resolve_kubeconfig_paths() -> Vec<PathBuf> {
    if let Ok(kc) = env::var("KUBECONFIG") {
        let list: Vec<PathBuf> = kc
            .split(':')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    let home = env::var("HOME").unwrap_or_default();
    vec![PathBuf::from(home).join(".kube").join("config")]
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        return t[1..t.len() - 1].to_string();
    }
    t.to_string()
}

struct ParsedKubeDoc {
    current_context: String,
    contexts: Vec<(String, String, String)>, // (name, namespace, cluster)
    clusters: HashMap<String, String>,       // cluster_name -> server URL
}

fn parse_kubeconfig_json_doc(raw: &str) -> Result<ParsedKubeDoc, String> {
    let val = parse_json(raw)?;
    if !matches!(val, Value::Object(_)) {
        return Err("JSON kubeconfig root must be an object".into());
    }
    let current_context = val
        .get("current-context")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut contexts = Vec::new();
    if let Some(arr) = val.get("contexts").and_then(Value::as_array) {
        for item in arr {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if name.is_empty() {
                continue;
            }
            let ctx_obj = item.get("context");
            let cluster = ctx_obj
                .and_then(|c| c.get("cluster"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            let ns_raw = ctx_obj
                .and_then(|c| c.get("namespace"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let namespace = if ns_raw.is_empty() {
                "default".to_string()
            } else {
                ns_raw.to_string()
            };
            contexts.push((name, namespace, cluster));
        }
    }

    let mut clusters = HashMap::new();
    if let Some(arr) = val.get("clusters").and_then(Value::as_array) {
        for item in arr {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if name.is_empty() {
                continue;
            }
            let server = item
                .get("cluster")
                .and_then(|c| c.get("server"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            clusters.entry(name).or_insert(server);
        }
    }

    Ok(ParsedKubeDoc {
        current_context,
        contexts,
        clusters,
    })
}

fn parse_kubeconfig_doc(raw: &str) -> Result<ParsedKubeDoc, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(ParsedKubeDoc {
            current_context: String::new(),
            contexts: Vec::new(),
            clusters: HashMap::new(),
        });
    }
    if trimmed.starts_with('{') {
        return parse_kubeconfig_json_doc(trimmed);
    }
    parse_single_yaml_kubeconfig(raw)
}

fn parse_single_yaml_kubeconfig(raw: &str) -> Result<ParsedKubeDoc, String> {
    let mut current_context = String::new();
    let mut contexts: Vec<(String, String, String)> = Vec::new();
    let mut clusters: HashMap<String, String> = HashMap::new();
    let mut saw_known_top_key = false;
    let mut saw_content = false;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Contexts,
        Clusters,
    }

    let mut section = Section::None;
    let mut cur_name = String::new();
    let mut cur_ns = String::new();
    let mut cur_cluster = String::new();
    let mut cur_server = String::new();
    let mut has_item = false;

    let flush = |section: Section,
                 has_item: &mut bool,
                 cur_name: &mut String,
                 cur_ns: &mut String,
                 cur_cluster: &mut String,
                 cur_server: &mut String,
                 contexts: &mut Vec<(String, String, String)>,
                 clusters: &mut HashMap<String, String>| {
        if *has_item && !cur_name.is_empty() {
            match section {
                Section::Contexts => {
                    let ns = if cur_ns.is_empty() {
                        "default".to_string()
                    } else {
                        cur_ns.clone()
                    };
                    contexts.push((cur_name.clone(), ns, cur_cluster.clone()));
                }
                Section::Clusters => {
                    clusters
                        .entry(cur_name.clone())
                        .or_insert_with(|| cur_server.clone());
                }
                Section::None => {}
            }
        }
        *has_item = false;
        cur_name.clear();
        cur_ns.clear();
        cur_cluster.clear();
        cur_server.clear();
    };

    for line in raw.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if stripped == "---" {
            if saw_content {
                return Err("multi-document YAML kubeconfig requires kubectl".into());
            }
            continue;
        }
        saw_content = true;
        let indent = line.len() - line.trim_start().len();

        if indent == 0 && !(section != Section::None && stripped.starts_with("- ")) {
            if section != Section::None {
                flush(
                    section,
                    &mut has_item,
                    &mut cur_name,
                    &mut cur_ns,
                    &mut cur_cluster,
                    &mut cur_server,
                    &mut contexts,
                    &mut clusters,
                );
                section = Section::None;
            }
            if let Some(val) = stripped.strip_prefix("current-context:") {
                saw_known_top_key = true;
                let v = val.trim();
                if v.starts_with('&') || v.starts_with('*') || v.starts_with('|') || v.starts_with('>') {
                    return Err("unsupported YAML current-context syntax".into());
                }
                current_context = unquote(v);
            } else if let Some(rest) = stripped.strip_prefix("contexts:") {
                saw_known_top_key = true;
                let r = rest.trim();
                if r.is_empty() {
                    section = Section::Contexts;
                } else if r == "[]" || r == "null" || r == "~" {
                    section = Section::None;
                } else {
                    return Err("unsupported inline YAML contexts syntax".into());
                }
            } else if let Some(rest) = stripped.strip_prefix("clusters:") {
                saw_known_top_key = true;
                let r = rest.trim();
                if r.is_empty() {
                    section = Section::Clusters;
                } else if r == "[]" || r == "null" || r == "~" {
                    section = Section::None;
                } else {
                    return Err("unsupported inline YAML clusters syntax".into());
                }
            } else if stripped.starts_with("apiVersion:")
                || stripped.starts_with("kind:")
                || stripped.starts_with("users:")
                || stripped.starts_with("preferences:")
            {
                saw_known_top_key = true;
            }
            continue;
        }

        if section == Section::None {
            continue;
        }

        if let Some(rest) = stripped.strip_prefix("- ") {
            let rt = rest.trim();
            if rt.starts_with('{') || rt.starts_with('&') || rt.starts_with('*') {
                return Err("unsupported YAML flow/anchor syntax in kubeconfig".into());
            }
            flush(
                section,
                &mut has_item,
                &mut cur_name,
                &mut cur_ns,
                &mut cur_cluster,
                &mut cur_server,
                &mut contexts,
                &mut clusters,
            );
            has_item = true;
            if let Some(v) = rt.strip_prefix("name:") {
                cur_name = unquote(v);
            } else if let Some(v) = rt.strip_prefix("server:") {
                cur_server = unquote(v);
            } else if let Some(v) = rt.strip_prefix("context:")
                && v.trim().starts_with('{')
            {
                return Err("unsupported inline YAML context mapping".into());
            }
        } else if let Some(v) = stripped.strip_prefix("context:")
            && v.trim().starts_with('{')
        {
            return Err("unsupported inline YAML context mapping".into());
        } else if let Some(v) = stripped.strip_prefix("cluster:") {
            let vt = v.trim();
            if vt.starts_with('{') {
                return Err("unsupported inline YAML cluster mapping".into());
            }
            if section == Section::Contexts && !vt.is_empty() {
                cur_cluster = unquote(vt);
            }
        } else if let Some(v) = stripped.strip_prefix("name:") {
            if cur_name.is_empty() {
                cur_name = unquote(v);
            }
        } else if let Some(v) = stripped.strip_prefix("namespace:") {
            cur_ns = unquote(v);
        } else if let Some(v) = stripped.strip_prefix("server:") {
            cur_server = unquote(v);
        }
    }
    if section != Section::None {
        flush(
            section,
            &mut has_item,
            &mut cur_name,
            &mut cur_ns,
            &mut cur_cluster,
            &mut cur_server,
            &mut contexts,
            &mut clusters,
        );
    }

    if saw_content && !saw_known_top_key {
        return Err("unrecognized kubeconfig format".into());
    }

    Ok(ParsedKubeDoc {
        current_context,
        contexts,
        clusters,
    })
}

/// Merge multiple kubeconfig documents (JSON or YAML) using kubectl's
/// first-value-wins precedence. If ANY document cannot be safely parsed,
/// fails closed with `target_unknown = true` so a later file's non-prod
/// context is never shown in place of an unreadable earlier file.
pub fn merge_kubeconfigs(docs: &[&str], aws_profile: String) -> KubeState {
    let mut parsed_docs = Vec::with_capacity(docs.len());
    for (idx, doc_str) in docs.iter().enumerate() {
        match parse_kubeconfig_doc(doc_str) {
            Ok(doc) => parsed_docs.push(doc),
            Err(err) => {
                return KubeState::unknown(
                    aws_profile,
                    format!("kubeconfig #{} could not be parsed safely: {err}", idx + 1),
                );
            }
        }
    }
    finalize_merged_docs(parsed_docs, aws_profile)
}

fn finalize_merged_docs(parsed_docs: Vec<ParsedKubeDoc>, aws_profile: String) -> KubeState {
    let mut current_context = String::new();
    let mut raw_contexts: Vec<(String, String, String)> = Vec::new();
    let mut seen_contexts: HashSet<String> = HashSet::new();
    let mut merged_clusters: HashMap<String, String> = HashMap::new();

    for parsed in parsed_docs {
        if current_context.is_empty() && !parsed.current_context.is_empty() {
            current_context = parsed.current_context;
        }
        for (cname, server) in parsed.clusters {
            merged_clusters.entry(cname).or_insert(server);
        }
        for (name, ns, cluster) in parsed.contexts {
            if seen_contexts.insert(name.clone()) {
                raw_contexts.push((name, ns, cluster));
            }
        }
    }

    let contexts: Vec<KubeContext> = raw_contexts
        .into_iter()
        .map(|(name, namespace, cluster)| {
            let server = merged_clusters
                .get(&cluster)
                .map(String::as_str)
                .unwrap_or("");
            let is_prod = is_prod_name(&name) || is_prod_name(&cluster) || is_prod_name(server);
            KubeContext {
                name,
                namespace,
                cluster,
                is_prod,
            }
        })
        .collect();

    let current_entry = contexts.iter().find(|c| c.name == current_context);
    let current_namespace = current_entry
        .map(|c| c.namespace.clone())
        .unwrap_or_else(|| "default".into());
    let current_is_prod = current_entry
        .map(|c| c.is_prod)
        .unwrap_or_else(|| is_prod_name(&current_context));

    KubeState {
        available: !contexts.is_empty() || !current_context.is_empty(),
        target_unknown: false,
        warning_detail: String::new(),
        current_context,
        current_namespace,
        current_is_prod,
        contexts,
        aws_profile,
    }
}

#[cfg(test)]
pub fn parse_kubeconfig(raw: &str, aws_profile: String) -> KubeState {
    merge_kubeconfigs(&[raw], aws_profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kubeconfig_and_flags_prod_contexts() {
        let yaml = r#"
apiVersion: v1
kind: Config
current-context: eks-prod-us-east
contexts:
- context:
    cluster: aws-prod-cluster
    namespace: payments
    user: admin
  name: eks-prod-us-east
- name: minikube-dev
  context:
    cluster: minikube
    namespace: dev
users:
- name: admin
"#;
        let state = parse_kubeconfig(yaml, "staging".into());
        assert!(state.available);
        assert!(!state.target_unknown);
        assert_eq!(state.current_context, "eks-prod-us-east");
        assert_eq!(state.current_namespace, "payments");
        assert!(state.current_is_prod);
        assert_eq!(state.contexts.len(), 2);
        assert!(state.contexts[0].is_prod);
        assert!(!state.contexts[1].is_prod);
        assert_eq!(state.aws_profile, "staging");
    }

    #[test]
    fn merges_json_prod_kubeconfig_before_yaml_dev_kubeconfig() {
        let first_json_prod = r#"{
          "apiVersion": "v1",
          "kind": "Config",
          "current-context": "eks-prod",
          "contexts": [
            {"name": "eks-prod", "context": {"cluster": "aws-prod", "namespace": "payments"}}
          ],
          "clusters": [
            {"name": "aws-prod", "cluster": {"server": "https://prod.k8s.example:6443"}}
          ]
        }"#;
        let second_yaml_dev = r#"
apiVersion: v1
kind: Config
current-context: local-dev
contexts:
- name: local-dev
  context:
    cluster: kind-dev
    namespace: dev
"#;
        let state = merge_kubeconfigs(&[first_json_prod, second_yaml_dev], String::new());
        assert!(state.available);
        assert!(!state.target_unknown);
        assert_eq!(state.current_context, "eks-prod");
        assert_eq!(state.current_namespace, "payments");
        assert!(state.current_is_prod);
        assert_eq!(state.contexts.len(), 2);
    }

    #[test]
    fn fails_closed_as_unknown_when_earlier_kubeconfig_uses_unsupported_syntax() {
        let first_inline_yaml = r#"
apiVersion: v1
kind: Config
current-context: prod-cluster
contexts: [{name: prod-cluster, context: {cluster: prod}}]
"#;
        let second_yaml_dev = r#"
apiVersion: v1
kind: Config
current-context: local-dev
contexts:
- name: local-dev
  context:
    cluster: kind-dev
    namespace: dev
"#;
        let state = merge_kubeconfigs(&[first_inline_yaml, second_yaml_dev], String::new());
        assert!(state.available);
        assert!(state.target_unknown);
        assert!(state.current_context.is_empty());
        assert!(!state.warning_detail.is_empty());
    }

    #[test]
    fn merges_multiple_kubeconfig_files_and_catches_prod_in_later_files() {
        let first_dev_only = r#"
apiVersion: v1
kind: Config
contexts:
- name: local-dev
  context:
    cluster: kind-dev
    namespace: dev
"#;
        let second_selects_prod = r#"
apiVersion: v1
kind: Config
current-context: primary
contexts:
- name: primary
  context:
    cluster: main-cluster
    namespace: billing
clusters:
- name: main-cluster
  cluster:
    server: https://k8s.prod.internal.example:6443
"#;
        let state = merge_kubeconfigs(&[first_dev_only, second_selects_prod], String::new());
        assert!(state.available);
        assert!(!state.target_unknown);
        assert_eq!(state.current_context, "primary");
        assert_eq!(state.current_namespace, "billing");
        assert!(state.current_is_prod);
        assert_eq!(state.contexts.len(), 2);
    }

    #[test]
    fn first_non_empty_current_context_wins_while_merging_context_definitions() {
        let first_sets_ctx = r#"
apiVersion: v1
kind: Config
current-context: shared-ctx
"#;
        let second_defines_prod_ctx = r#"
apiVersion: v1
kind: Config
current-context: local-dev
contexts:
- name: shared-ctx
  context:
    cluster: eks-production-eu
    namespace: core
"#;
        let state = merge_kubeconfigs(&[first_sets_ctx, second_defines_prod_ctx], String::new());
        assert!(!state.target_unknown);
        assert_eq!(state.current_context, "shared-ctx");
        assert!(state.current_is_prod);
        assert_eq!(state.current_namespace, "core");
    }

    #[test]
    fn prod_detection_matches_word_boundaries_only() {
        assert!(is_prod_name("aws-prod-1"));
        assert!(is_prod_name("production_eu"));
        assert!(is_prod_name("gke_prd_core"));
        assert!(!is_prod_name("product-catalog-dev"));
        assert!(!is_prod_name("reproduce-staging"));
    }
}
