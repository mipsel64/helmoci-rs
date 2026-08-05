use super::HelmError;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
struct ChartIndex {
    entries: Option<HashMap<String, Vec<ChartEntry>>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChartEntry {
    pub version: Option<String>,
    pub urls: Option<Vec<String>>,
}

pub fn chart_entries(
    index_text: &str,
    repo_url: &str,
    chart_name: &str,
) -> Result<Vec<ChartEntry>, HelmError> {
    let index: ChartIndex = serde_yaml_ng::from_str(index_text).map_err(|_| {
        HelmError::InvalidIndex(format!(
            "Upstream {repo_url} did not return a valid Helm index.yaml. \
             Check that the path maps to a classic Helm repo."
        ))
    })?;
    let Some(entries) = index.entries else {
        return Err(HelmError::InvalidIndex(format!(
            "No Helm chart index found at {repo_url}. \
             Expected {repo_url}/index.yaml with an \"entries\" map."
        )));
    };
    match entries.get(chart_name) {
        Some(list) if !list.is_empty() => Ok(list.clone()),
        _ => {
            let mut available: Vec<&String> = entries.keys().collect();
            available.sort();
            let shown: Vec<&str> = available.iter().take(8).map(|s| s.as_str()).collect();
            let hint = if shown.is_empty() {
                String::new()
            } else {
                let more = if available.len() > 8 { ", …" } else { "" };
                format!(" Charts in this repo include: {}{more}.", shown.join(", "))
            };
            Err(HelmError::NotFound(format!(
                "Chart \"{chart_name}\" was not found in {repo_url}.{hint} \
                 The chart name is the last path segment."
            )))
        }
    }
}

/// Versions as published (newest first in well-formed indexes), deduped.
pub fn list_versions(
    index_text: &str,
    repo_url: &str,
    chart_name: &str,
) -> Result<Vec<String>, HelmError> {
    let entries = chart_entries(index_text, repo_url, chart_name)?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries {
        if let Some(v) = entry.version {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    Ok(out)
}

pub fn resolve_chart_url(
    index_text: &str,
    repo_url: &str,
    chart_name: &str,
    version: &str,
) -> Result<String, HelmError> {
    let entries = chart_entries(index_text, repo_url, chart_name)?;
    let entry = entries
        .iter()
        .find(|e| e.version.as_deref() == Some(version))
        .ok_or_else(|| {
            HelmError::NotFound(format!(
                "Version \"{version}\" was not found for chart \"{chart_name}\" in {repo_url}. \
                 List available versions: GET /v2/<name>/tags/list"
            ))
        })?;
    let raw = entry.urls.as_ref().and_then(|u| u.first()).ok_or_else(|| {
        HelmError::NotFound(format!(
            "Chart \"{chart_name}\" version \"{version}\" in {repo_url} \
                 has no download URL in index.yaml."
        ))
    })?;
    if raw.starts_with("http://") || raw.starts_with("https://") {
        Ok(raw.clone())
    } else {
        Ok(format!(
            "{}/{}",
            repo_url.trim_end_matches('/'),
            raw.trim_start_matches('/')
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: &str = r#"
apiVersion: v1
entries:
  demo:
    - name: demo
      version: 2.0.0
      created: "2024-01-01T00:00:00Z"
      urls: ["https://cdn.example.com/demo-2.0.0.tgz"]
    - name: demo
      version: 1.0.0
      urls: ["charts/demo-1.0.0.tgz"]
    - name: demo
      version: 1.0.0
      urls: ["dup.tgz"]
  other:
    - name: other
      version: 0.1.0
      urls: ["other-0.1.0.tgz"]
"#;

    const REPO: &str = "https://repo.example.com/stable";

    #[test]
    fn lists_versions_deduped_in_index_order() {
        let versions = list_versions(INDEX, REPO, "demo").unwrap();
        assert_eq!(versions, vec!["2.0.0", "1.0.0"]);
    }

    #[test]
    fn resolves_absolute_and_relative_urls() {
        assert_eq!(
            resolve_chart_url(INDEX, REPO, "demo", "2.0.0").unwrap(),
            "https://cdn.example.com/demo-2.0.0.tgz"
        );
        assert_eq!(
            resolve_chart_url(INDEX, REPO, "demo", "1.0.0").unwrap(),
            "https://repo.example.com/stable/charts/demo-1.0.0.tgz"
        );
    }

    #[test]
    fn missing_chart_lists_available() {
        let err = list_versions(INDEX, REPO, "nope").unwrap_err();
        let HelmError::NotFound(msg) = err else {
            panic!("wrong variant: {err:?}")
        };
        assert!(
            msg.contains("Charts in this repo include: demo, other"),
            "{msg}"
        );
    }

    #[test]
    fn missing_version_is_not_found() {
        let err = resolve_chart_url(INDEX, REPO, "demo", "9.9.9").unwrap_err();
        assert!(matches!(err, HelmError::NotFound(_)));
    }

    #[test]
    fn invalid_yaml_and_missing_entries_are_invalid_index() {
        assert!(matches!(
            list_versions(": not yaml [", REPO, "demo").unwrap_err(),
            HelmError::InvalidIndex(_)
        ));
        assert!(matches!(
            list_versions("apiVersion: v1", REPO, "demo").unwrap_err(),
            HelmError::InvalidIndex(_)
        ));
    }
}
