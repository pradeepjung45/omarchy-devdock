//! Native zero-dependency kubeconfig reader + PROD context safety guard
//! + AWS profile inspection. Merges all colon-separated `$KUBECONFIG` files
//! using kubectl precedence rules. Never makes network calls.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::json::Json;

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
    pub current_context: String,
    pub current_namespace: String,
    pub current_is_prod: bool,
    pub contexts: Vec<KubeContext>,
    pub aws_profile: String,
}

impl KubeState {
    pub fn collect() -> Self {
        let aws_profile = env::var("AWS_PROFILE")
            .or_else(|_| env::var("AWS_DEFAULT_PROFILE"))
            .unwrap_or_default();

        let paths = resolve_kubeconfig_paths();
        let mut docs: Vec<String> = Vec::new();
        for path in paths {
            if let Ok(raw) = fs::read_to_string(&path) {
                docs.push(raw);
            }
        }
        if docs.is_empty() {
            return Self {
                available: false,
                current_context: String::new(),
                current_namespace: String::new(),
                current_is_prod: false,
                contexts: Vec::new(),
                aws_profile,
            };
        }

        let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
        merge_kubeconfigs(&refs, aws_profile)
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("available", Json::Bool(self.available)),
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

fn parse_single_kubeconfig(raw: &str) -> ParsedKubeDoc {
    let mut current_context = String::new();
    let mut contexts: Vec<(String, String, String)> = Vec::new();
    let mut clusters: HashMap<String, String> = HashMap::new();

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
                current_context = unquote(val);
            } else if stripped == "contexts:" {
                section = Section::Contexts;
            } else if stripped == "clusters:" {
                section = Section::Clusters;
            }
            continue;
        }

        if section == Section::None {
            continue;
        }

        if let Some(rest) = stripped.strip_prefix("- ") {
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
            if let Some(v) = rest.trim().strip_prefix("name:") {
                cur_name = unquote(v);
            } else if let Some(v) = rest.trim().strip_prefix("server:") {
                cur_server = unquote(v);
            }
        } else if let Some(v) = stripped.strip_prefix("name:") {
            if cur_name.is_empty() {
                cur_name = unquote(v);
            }
        } else if let Some(v) = stripped.strip_prefix("namespace:") {
            cur_ns = unquote(v);
        } else if let Some(v) = stripped.strip_prefix("cluster:") {
            cur_cluster = unquote(v);
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

    ParsedKubeDoc {
        current_context,
        contexts,
        clusters,
    }
}

/// Merge multiple kubeconfig YAML documents using kubectl's first-value-wins
/// merge semantics: the first non-empty `current-context` wins, and contexts
/// and clusters are unioned across all files (first definition per name wins).
pub fn merge_kubeconfigs(docs: &[&str], aws_profile: String) -> KubeState {
    let mut current_context = String::new();
    let mut raw_contexts: Vec<(String, String, String)> = Vec::new();
    let mut seen_contexts: HashSet<String> = HashSet::new();
    let mut merged_clusters: HashMap<String, String> = HashMap::new();

    for doc_str in docs {
        let parsed = parse_single_kubeconfig(doc_str);
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
        assert_eq!(state.current_context, "eks-prod-us-east");
        assert_eq!(state.current_namespace, "payments");
        assert!(state.current_is_prod);
        assert_eq!(state.contexts.len(), 2);
        assert!(state.contexts[0].is_prod);
        assert!(!state.contexts[1].is_prod);
        assert_eq!(state.aws_profile, "staging");
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
