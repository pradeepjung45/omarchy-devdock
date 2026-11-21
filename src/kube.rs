//! Native zero-dependency `~/.kube/config` reader + PROD context safety guard
//! + AWS profile inspection. Never makes network calls.

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

        let path = resolve_kubeconfig_path();
        let Ok(raw) = fs::read_to_string(&path) else {
            return Self {
                available: false,
                current_context: String::new(),
                current_namespace: String::new(),
                current_is_prod: false,
                contexts: Vec::new(),
                aws_profile,
            };
        };

        parse_kubeconfig(&raw, aws_profile)
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

fn resolve_kubeconfig_path() -> PathBuf {
    if let Ok(kc) = env::var("KUBECONFIG")
        && let Some(first) = kc.split(':').find(|s| !s.trim().is_empty())
    {
        return PathBuf::from(first.trim());
    }
    let home = env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".kube").join("config")
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

pub fn parse_kubeconfig(raw: &str, aws_profile: String) -> KubeState {
    let mut current_context = String::new();
    let mut contexts: Vec<KubeContext> = Vec::new();
    let mut in_contexts = false;
    let mut cur_name = String::new();
    let mut cur_ns = String::new();
    let mut cur_cluster = String::new();
    let mut has_item = false;

    let flush = |has_item: &mut bool,
                 cur_name: &mut String,
                 cur_ns: &mut String,
                 cur_cluster: &mut String,
                 contexts: &mut Vec<KubeContext>| {
        if *has_item && !cur_name.is_empty() {
            let ns = if cur_ns.is_empty() {
                "default".to_string()
            } else {
                cur_ns.clone()
            };
            let prod = is_prod_name(cur_name) || is_prod_name(cur_cluster);
            contexts.push(KubeContext {
                name: cur_name.clone(),
                namespace: ns,
                cluster: cur_cluster.clone(),
                is_prod: prod,
            });
        }
        *has_item = false;
        cur_name.clear();
        cur_ns.clear();
        cur_cluster.clear();
    };

    for line in raw.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();

        if indent == 0 && !(in_contexts && stripped.starts_with("- ")) {
            if in_contexts {
                flush(&mut has_item, &mut cur_name, &mut cur_ns, &mut cur_cluster, &mut contexts);
                in_contexts = false;
            }
            if let Some(val) = stripped.strip_prefix("current-context:") {
                current_context = unquote(val);
            } else if stripped == "contexts:" {
                in_contexts = true;
            }
            continue;
        }

        if !in_contexts {
            continue;
        }

        if let Some(rest) = stripped.strip_prefix("- ") {
            flush(&mut has_item, &mut cur_name, &mut cur_ns, &mut cur_cluster, &mut contexts);
            has_item = true;
            if let Some(v) = rest.trim().strip_prefix("name:") {
                cur_name = unquote(v);
            }
        } else if let Some(v) = stripped.strip_prefix("name:") {
            if cur_name.is_empty() {
                cur_name = unquote(v);
            }
        } else if let Some(v) = stripped.strip_prefix("namespace:") {
            cur_ns = unquote(v);
        } else if let Some(v) = stripped.strip_prefix("cluster:") {
            cur_cluster = unquote(v);
        }
    }
    if in_contexts {
        flush(&mut has_item, &mut cur_name, &mut cur_ns, &mut cur_cluster, &mut contexts);
    }

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
    fn prod_detection_matches_word_boundaries_only() {
        assert!(is_prod_name("aws-prod-1"));
        assert!(is_prod_name("production_eu"));
        assert!(is_prod_name("gke_prd_core"));
        assert!(!is_prod_name("product-catalog-dev"));
        assert!(!is_prod_name("reproduce-staging"));
    }
}
