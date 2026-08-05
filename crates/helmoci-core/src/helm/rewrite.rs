use super::HelmError;
use super::tgz::{is_root_chart_file, pack_tgz, unpack_tgz};
use crate::resolver::{is_public_hostname, normalize_repo_key};
use serde_yaml_ng::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct Rewrite {
    pub name: String,
    pub from: String,
    pub to: String,
}

pub struct RewriteResult {
    pub tgz: Vec<u8>,
    pub modified: bool,
    pub rewrites: Vec<Rewrite>,
}

/// Owned so the whole rewrite can run inside spawn_blocking.
#[derive(Debug, Clone, Default)]
pub struct RewriteContext {
    pub proxy_host: String,
    /// Normalized `host/path` -> alias name, for alias-form rewrites.
    pub classic_alias_by_repo: HashMap<String, String>,
}

/// Rewrite one dependency repository URL, or None to leave it untouched.
pub fn rewrite_dependency_url(repo_url: &str, ctx: &RewriteContext) -> Option<String> {
    if repo_url.is_empty()
        || repo_url.starts_with('@')
        || repo_url.starts_with("alias:")
        || repo_url.starts_with("file:")
        || repo_url.starts_with("oci://")
    {
        return None;
    }
    let parsed = url::Url::parse(repo_url).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?;
    if !is_public_hostname(host) {
        return None;
    }
    let key = normalize_repo_key(repo_url)?;
    if let Some(alias) = ctx.classic_alias_by_repo.get(&key) {
        return Some(format!("oci://{}/{}", ctx.proxy_host, alias));
    }
    Some(format!("oci://{}/{}", ctx.proxy_host, key))
}

/// Rewrite Chart.yaml (and Chart.lock) dependency repos to oci:// proxy URLs.
/// Comments in the YAML are lost on rewrite — same behavior as upstream helmoci.
pub fn rewrite_chart_dependencies(
    tgz: &[u8],
    ctx: &RewriteContext,
) -> Result<RewriteResult, HelmError> {
    fn unmodified(tgz: &[u8]) -> RewriteResult {
        RewriteResult {
            tgz: tgz.to_vec(),
            modified: false,
            rewrites: Vec::new(),
        }
    }

    if ctx.proxy_host.is_empty() {
        return Ok(unmodified(tgz));
    }
    let mut files = unpack_tgz(tgz)?;
    let Some(chart_idx) = files
        .iter()
        .position(|f| is_root_chart_file(&f.name, "Chart.yaml"))
    else {
        return Ok(unmodified(tgz));
    };
    let chart_text = String::from_utf8_lossy(&files[chart_idx].data).into_owned();
    let Ok(mut chart_value) = serde_yaml_ng::from_str::<Value>(&chart_text) else {
        return Ok(unmodified(tgz));
    };

    let dep_key = Value::String("dependencies".into());
    let mut rewrites = Vec::new();
    let modified = match chart_value.as_mapping_mut() {
        Some(map) => rewrite_deps_list(map.get_mut(&dep_key), ctx, Some(&mut rewrites)),
        None => false,
    };
    if !modified {
        return Ok(unmodified(tgz));
    }
    files[chart_idx].data = serde_yaml_ng::to_string(&chart_value)
        .map_err(|e| HelmError::InvalidChart(format!("failed to re-encode Chart.yaml: {e}")))?
        .into_bytes();

    if let Some(lock_idx) = files
        .iter()
        .position(|f| is_root_chart_file(&f.name, "Chart.lock"))
    {
        let lock_text = String::from_utf8_lossy(&files[lock_idx].data).into_owned();
        if let Ok(mut lock_value) = serde_yaml_ng::from_str::<Value>(&lock_text) {
            let lock_modified = match lock_value.as_mapping_mut() {
                Some(map) => rewrite_deps_list(map.get_mut(&dep_key), ctx, None),
                None => false,
            };
            if lock_modified && let Ok(text) = serde_yaml_ng::to_string(&lock_value) {
                files[lock_idx].data = text.into_bytes();
            }
        }
    }

    Ok(RewriteResult {
        tgz: pack_tgz(&files)?,
        modified: true,
        rewrites,
    })
}

fn rewrite_deps_list(
    deps: Option<&mut Value>,
    ctx: &RewriteContext,
    mut rewrites: Option<&mut Vec<Rewrite>>,
) -> bool {
    let Some(Value::Sequence(seq)) = deps else {
        return false;
    };
    let repo_key = Value::String("repository".into());
    let name_key = Value::String("name".into());
    let mut modified = false;
    for dep in seq.iter_mut() {
        let Some(map) = dep.as_mapping_mut() else {
            continue;
        };
        let Some(Value::String(repo)) = map.get(&repo_key).cloned() else {
            continue;
        };
        let Some(next) = rewrite_dependency_url(&repo, ctx) else {
            continue;
        };
        if next == repo {
            continue;
        }
        if let Some(list) = rewrites.as_deref_mut() {
            let name = map
                .get(&name_key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            list.push(Rewrite {
                name,
                from: repo.clone(),
                to: next.clone(),
            });
        }
        map.insert(repo_key.clone(), Value::String(next));
        modified = true;
    }
    modified
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helm::tgz::testutil::build_chart_tgz;

    fn ctx() -> RewriteContext {
        let mut aliases = HashMap::new();
        aliases.insert(
            "dandydeveloper.github.io/charts".to_string(),
            "dandy".to_string(),
        );
        RewriteContext {
            proxy_host: "proxy.test".to_string(),
            classic_alias_by_repo: aliases,
        }
    }

    #[test]
    fn rewrites_classic_urls() {
        assert_eq!(
            rewrite_dependency_url("https://charts.bitnami.com/bitnami/", &ctx()).unwrap(),
            "oci://proxy.test/charts.bitnami.com/bitnami"
        );
        assert_eq!(
            rewrite_dependency_url("https://charts.jetstack.io", &ctx()).unwrap(),
            "oci://proxy.test/charts.jetstack.io"
        );
    }

    #[test]
    fn prefers_alias_form_when_upstream_matches() {
        assert_eq!(
            rewrite_dependency_url("https://dandydeveloper.github.io/charts/", &ctx()).unwrap(),
            "oci://proxy.test/dandy"
        );
    }

    #[test]
    fn skips_non_rewritable_refs() {
        for url in [
            "",
            "@myrepo",
            "alias:myrepo",
            "file://../local",
            "oci://ghcr.io/x",
            "https://localhost/charts",
            "https://10.0.0.8/charts",
            "ftp://x.io/y",
        ] {
            assert!(rewrite_dependency_url(url, &ctx()).is_none(), "{url}");
        }
    }

    #[test]
    fn rewrites_chart_and_lock_in_tgz() {
        let chart_yaml = concat!(
            "name: demo\nversion: 1.0.0\ndependencies:\n",
            "  - name: redis\n    version: 17.0.0\n    repository: https://charts.bitnami.com/bitnami\n",
            "  - name: keep\n    version: 1.0.0\n    repository: oci://ghcr.io/keep\n",
        );
        let lock_yaml = concat!(
            "dependencies:\n",
            "  - name: redis\n    version: 17.0.0\n    repository: https://charts.bitnami.com/bitnami\n",
            "digest: sha256:aaaa\n",
        );
        let tgz = build_chart_tgz(&[
            ("demo/Chart.yaml", chart_yaml),
            ("demo/Chart.lock", lock_yaml),
            ("demo/values.yaml", "replicas: 1\n"),
        ]);

        let result = rewrite_chart_dependencies(&tgz, &ctx()).unwrap();
        assert!(result.modified);
        assert_eq!(result.rewrites.len(), 1);
        assert_eq!(result.rewrites[0].name, "redis");
        assert_eq!(
            result.rewrites[0].to,
            "oci://proxy.test/charts.bitnami.com/bitnami"
        );

        let files = unpack_tgz(&result.tgz).unwrap();
        let chart = files.iter().find(|f| f.name == "demo/Chart.yaml").unwrap();
        let value: Value = serde_yaml_ng::from_str(&String::from_utf8_lossy(&chart.data)).unwrap();
        let deps = value["dependencies"].as_sequence().unwrap();
        assert_eq!(
            deps[0]["repository"].as_str().unwrap(),
            "oci://proxy.test/charts.bitnami.com/bitnami"
        );
        assert_eq!(
            deps[1]["repository"].as_str().unwrap(),
            "oci://ghcr.io/keep"
        );
        let lock = files.iter().find(|f| f.name == "demo/Chart.lock").unwrap();
        let lock_value: Value =
            serde_yaml_ng::from_str(&String::from_utf8_lossy(&lock.data)).unwrap();
        assert_eq!(
            lock_value["dependencies"][0]["repository"]
                .as_str()
                .unwrap(),
            "oci://proxy.test/charts.bitnami.com/bitnami"
        );
        let values = files.iter().find(|f| f.name == "demo/values.yaml").unwrap();
        assert_eq!(values.data, b"replicas: 1\n");
    }

    #[test]
    fn unmodified_chart_returns_original_bytes() {
        let tgz = build_chart_tgz(&[("demo/Chart.yaml", "name: demo\nversion: 1.0.0\n")]);
        let result = rewrite_chart_dependencies(&tgz, &ctx()).unwrap();
        assert!(!result.modified);
        assert_eq!(result.tgz, tgz);
    }
}
