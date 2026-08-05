pub mod hostname;

pub use hostname::is_public_hostname;

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamAuthKind {
    #[default]
    None,
    Gcp,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AliasUpstream {
    /// Classic Helm repo, normalized with no trailing slash (http allowed for
    /// explicitly configured upstreams; host-path resolution stays https-only).
    Classic { repo_url: String },
    /// OCI registry upstream: `registry` = host[:port], `repo` = repo path.
    Oci { registry: String, repo: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alias {
    pub upstream: AliasUpstream,
    pub store: bool,
    pub auth: UpstreamAuthKind,
    pub plain_http: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicSource {
    ConfiguredAlias,
    HostPath,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassicChart {
    pub repo_url: String,
    pub chart_name: String,
    pub full_name: String,
    /// true when the chart comes from a `store: false` classic alias.
    pub ephemeral: bool,
    pub source: ClassicSource,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OciTarget {
    pub registry: String,
    /// Full upstream repo (alias repo + requested segments).
    pub repo: String,
    pub full_name: String,
    pub store: bool,
    pub auth: UpstreamAuthKind,
    pub plain_http: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    Classic(ClassicChart),
    Oci(OciTarget),
}

pub fn is_valid_chart_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Alias names must not look like hostnames: no dots allowed.
pub fn is_valid_alias_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn parse_alias_upstream(s: &str) -> Result<AliasUpstream, String> {
    if let Some(rest) = s.strip_prefix("oci://") {
        let rest = rest.trim_matches('/');
        let (registry, repo) = rest
            .split_once('/')
            .ok_or_else(|| format!("oci upstream needs a repo path: {s}"))?;
        if registry.is_empty() || repo.is_empty() {
            return Err(format!("invalid oci upstream: {s}"));
        }
        return Ok(AliasUpstream::Oci {
            registry: registry.to_string(),
            repo: repo.trim_matches('/').to_string(),
        });
    }
    if s.starts_with("https://") || s.starts_with("http://") {
        let parsed = url::Url::parse(s).map_err(|e| format!("invalid upstream url {s}: {e}"))?;
        parsed
            .host_str()
            .ok_or_else(|| format!("upstream url has no host: {s}"))?;
        return Ok(AliasUpstream::Classic {
            repo_url: s.trim_end_matches('/').to_string(),
        });
    }
    Err(format!(
        "alias upstream must start with oci://, https:// or http://: {s}"
    ))
}

/// `host[/path]` key used to match dependency URLs against classic alias upstreams.
pub fn normalize_repo_key(url_str: &str) -> Option<String> {
    let parsed = url::Url::parse(url_str).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let path = parsed.path().trim_matches('/');
    Some(if path.is_empty() {
        host
    } else {
        format!("{host}/{path}")
    })
}

pub fn classic_alias_rewrite_map(aliases: &HashMap<String, Alias>) -> HashMap<String, String> {
    aliases
        .iter()
        .filter_map(|(name, alias)| match &alias.upstream {
            AliasUpstream::Classic { repo_url } => {
                Some((normalize_repo_key(repo_url)?, name.clone()))
            }
            AliasUpstream::Oci { .. } => None,
        })
        .collect()
}

pub fn resolve_name(name: &str, aliases: &HashMap<String, Alias>) -> Option<Resolved> {
    let segments: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
    let first = *segments.first()?;

    if let Some(alias) = aliases.get(first) {
        return match &alias.upstream {
            AliasUpstream::Classic { repo_url } => {
                if segments.len() != 2 || !is_valid_chart_name(segments[1]) {
                    return None;
                }
                Some(Resolved::Classic(ClassicChart {
                    repo_url: repo_url.clone(),
                    chart_name: segments[1].to_string(),
                    full_name: name.to_string(),
                    ephemeral: !alias.store,
                    source: ClassicSource::ConfiguredAlias,
                }))
            }
            AliasUpstream::Oci { registry, repo } => {
                if segments.len() < 2 {
                    return None;
                }
                Some(Resolved::Oci(OciTarget {
                    registry: registry.clone(),
                    repo: format!("{}/{}", repo, segments[1..].join("/")),
                    full_name: name.to_string(),
                    store: alias.store,
                    auth: alias.auth.clone(),
                    plain_http: alias.plain_http,
                }))
            }
        };
    }

    resolve_host_path(&segments, name)
}

fn resolve_host_path(segments: &[&str], name: &str) -> Option<Resolved> {
    if segments.len() < 2 {
        return None;
    }
    let host = segments[0];
    if !is_public_hostname(host) {
        return None;
    }
    let chart_name = segments[segments.len() - 1];
    if !is_valid_chart_name(chart_name) {
        return None;
    }
    let repo_path = &segments[1..segments.len() - 1];
    if !repo_path.iter().all(|p| is_valid_chart_name(p)) {
        return None;
    }
    let repo_url = if repo_path.is_empty() {
        format!("https://{host}")
    } else {
        format!("https://{host}/{}", repo_path.join("/"))
    };
    Some(Resolved::Classic(ClassicChart {
        repo_url,
        chart_name: chart_name.to_string(),
        full_name: name.to_string(),
        ephemeral: false,
        source: ClassicSource::HostPath,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aliases() -> HashMap<String, Alias> {
        let mut m = HashMap::new();
        m.insert(
            "argo".to_string(),
            Alias {
                upstream: parse_alias_upstream("https://argoproj.github.io/argo-helm/").unwrap(),
                store: true,
                auth: UpstreamAuthKind::None,
                plain_http: false,
            },
        );
        m.insert(
            "meteora".to_string(),
            Alias {
                upstream: parse_alias_upstream("oci://asia-docker.pkg.dev/meteora-ops/charts")
                    .unwrap(),
                store: false,
                auth: UpstreamAuthKind::Gcp,
                plain_http: false,
            },
        );
        m
    }

    #[test]
    fn parses_alias_upstreams() {
        assert_eq!(
            parse_alias_upstream("https://charts.jetstack.io").unwrap(),
            AliasUpstream::Classic {
                repo_url: "https://charts.jetstack.io".into()
            }
        );
        assert_eq!(
            parse_alias_upstream("oci://asia-docker.pkg.dev/meteora-ops/charts").unwrap(),
            AliasUpstream::Oci {
                registry: "asia-docker.pkg.dev".into(),
                repo: "meteora-ops/charts".into()
            }
        );
        assert!(parse_alias_upstream("ftp://x.io").is_err());
        assert!(parse_alias_upstream("oci://registry-only").is_err());
    }

    #[test]
    fn resolves_host_path_form() {
        let r = resolve_name("argoproj.github.io/argo-helm/argo-cd", &HashMap::new()).unwrap();
        assert_eq!(
            r,
            Resolved::Classic(ClassicChart {
                repo_url: "https://argoproj.github.io/argo-helm".into(),
                chart_name: "argo-cd".into(),
                full_name: "argoproj.github.io/argo-helm/argo-cd".into(),
                ephemeral: false,
                source: ClassicSource::HostPath,
            })
        );
        let r = resolve_name("charts.jetstack.io/cert-manager", &HashMap::new()).unwrap();
        assert_eq!(
            r,
            Resolved::Classic(ClassicChart {
                repo_url: "https://charts.jetstack.io".into(),
                chart_name: "cert-manager".into(),
                full_name: "charts.jetstack.io/cert-manager".into(),
                ephemeral: false,
                source: ClassicSource::HostPath,
            })
        );
    }

    #[test]
    fn rejects_bad_host_path_names() {
        for name in [
            "single-segment.io",
            "localhost/x/chart",
            "10.0.0.1/chart",
            "a.io/bad name/c",
        ] {
            assert!(resolve_name(name, &HashMap::new()).is_none(), "{name}");
        }
    }

    #[test]
    fn resolves_classic_alias() {
        let r = resolve_name("argo/argo-cd", &aliases()).unwrap();
        assert_eq!(
            r,
            Resolved::Classic(ClassicChart {
                repo_url: "https://argoproj.github.io/argo-helm".into(),
                chart_name: "argo-cd".into(),
                full_name: "argo/argo-cd".into(),
                ephemeral: false,
                source: ClassicSource::ConfiguredAlias,
            })
        );
        assert!(resolve_name("argo/a/b", &aliases()).is_none());
        assert!(resolve_name("argo", &aliases()).is_none());
    }

    #[test]
    fn resolves_oci_alias() {
        let r = resolve_name("meteora/generic-app", &aliases()).unwrap();
        assert_eq!(
            r,
            Resolved::Oci(OciTarget {
                registry: "asia-docker.pkg.dev".into(),
                repo: "meteora-ops/charts/generic-app".into(),
                full_name: "meteora/generic-app".into(),
                store: false,
                auth: UpstreamAuthKind::Gcp,
                plain_http: false,
            })
        );
        assert!(resolve_name("meteora", &aliases()).is_none());
    }

    #[test]
    fn validates_names() {
        assert!(is_valid_chart_name("argo-cd"));
        assert!(is_valid_chart_name("chart.v2_x"));
        assert!(!is_valid_chart_name("-bad"));
        assert!(!is_valid_chart_name(""));
        assert!(is_valid_alias_name("meteora"));
        assert!(!is_valid_alias_name("has.dot"));
        assert!(!is_valid_alias_name(""));
    }

    #[test]
    fn builds_classic_alias_rewrite_map() {
        let map = classic_alias_rewrite_map(&aliases());
        assert_eq!(
            map.get("argoproj.github.io/argo-helm"),
            Some(&"argo".to_string())
        );
        assert_eq!(map.len(), 1);
    }
}
