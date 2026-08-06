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

/// Scheme, authority and path only. A repository URL may carry credentials in
/// userinfo or a signed token in its query, and these messages are rendered into
/// error bodies anonymous clients read, so both are dropped before the repository is
/// named. Anything unparseable is left out entirely.
fn sanitized_repo(repo_url: &str) -> Option<String> {
    let mut url = url::Url::parse(repo_url).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    Some(url.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disclosure {
    ClientSupplied,
    Hidden,
}

/// A classic Helm repository, plus whether its URL may be named in an error message a
/// client reads.
///
/// The two callers are asymmetric. In host-path form the client wrote the repository
/// host into its own reference, so echoing it back tells the client nothing it did not
/// supply. A configured alias exists to hide its upstream — which the operator may
/// have pointed at an internal repository — so its URL is never named to a client and
/// belongs in the operator's logs instead.
#[derive(Debug, Clone, Copy)]
pub struct IndexRepo<'a> {
    url: &'a str,
    disclosure: Disclosure,
}

impl<'a> IndexRepo<'a> {
    /// The client supplied this repository itself (host-path form).
    pub const fn client_supplied(url: &'a str) -> Self {
        Self {
            url,
            disclosure: Disclosure::ClientSupplied,
        }
    }

    /// This repository sits behind a configured alias and must stay hidden.
    pub const fn hidden(url: &'a str) -> Self {
        Self {
            url,
            disclosure: Disclosure::Hidden,
        }
    }

    /// `" at <sanitized repo>"`, or nothing when the repository must stay hidden or
    /// cannot be sanitized.
    fn suffix(&self) -> String {
        match self.disclosure {
            Disclosure::Hidden => String::new(),
            Disclosure::ClientSupplied => {
                sanitized_repo(self.url).map_or_else(String::new, |repo| format!(" at {repo}"))
            }
        }
    }
}

pub fn chart_entries(
    index_text: &str,
    repo: IndexRepo<'_>,
    chart_name: &str,
) -> Result<Vec<ChartEntry>, HelmError> {
    let index: ChartIndex = serde_yaml_ng::from_str(index_text).map_err(|_| {
        HelmError::InvalidIndex(format!(
            "Upstream{} did not return a valid Helm index.yaml. \
             Check that the path maps to a classic Helm repo.",
            repo.suffix()
        ))
    })?;
    let Some(entries) = index.entries else {
        return Err(HelmError::InvalidIndex(format!(
            "Upstream index.yaml{} did not contain an \"entries\" map.",
            repo.suffix()
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
                "Chart \"{chart_name}\" was not found{}.{hint} \
                 The chart name is the last path segment.",
                repo.suffix()
            )))
        }
    }
}

/// Versions as published (newest first in well-formed indexes), deduped.
pub fn list_versions(
    index_text: &str,
    repo: IndexRepo<'_>,
    chart_name: &str,
) -> Result<Vec<String>, HelmError> {
    let entries = chart_entries(index_text, repo, chart_name)?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries {
        if let Some(v) = entry.version
            && seen.insert(v.clone())
        {
            out.push(v);
        }
    }
    Ok(out)
}

pub fn resolve_chart_url(
    index_text: &str,
    repo: IndexRepo<'_>,
    chart_name: &str,
    version: &str,
) -> Result<String, HelmError> {
    let entries = chart_entries(index_text, repo, chart_name)?;
    let entry = entries
        .iter()
        .find(|e| e.version.as_deref() == Some(version))
        .ok_or_else(|| {
            HelmError::NotFound(format!(
                "Version \"{version}\" was not found for chart \"{chart_name}\"{}. \
                 List available versions: GET /v2/<name>/tags/list",
                repo.suffix()
            ))
        })?;
    let raw = entry.urls.as_ref().and_then(|u| u.first()).ok_or_else(|| {
        HelmError::NotFound(format!(
            "Chart \"{chart_name}\" version \"{version}\"{} \
                 has no download URL in index.yaml.",
            repo.suffix()
        ))
    })?;
    resolve_download_url(repo.url, raw, chart_name, version)
}

/// Absolute entries are used as-is. Relative entries resolve per RFC 3986, the same
/// as Helm's own `repo.ResolveReferenceURL`; upstream helmoci concatenates strings
/// instead, so a root-relative `/charts/x.tgz` resolves against the repository root
/// here and against the repository path upstream. A relative entry may never move
/// the download to another origin, which rules out scheme-relative `//host/x`
/// entries (the URL parser also strips spaces and tabs, so the origin is compared
/// after resolution rather than by inspecting the raw string).
fn resolve_download_url(
    repo_url: &str,
    raw: &str,
    chart_name: &str,
    version: &str,
) -> Result<String, HelmError> {
    if let Ok(absolute) = url::Url::parse(raw) {
        return Ok(absolute.to_string());
    }
    let mut base = url::Url::parse(repo_url)
        .map_err(|_| HelmError::InvalidIndex("Configured Helm repository URL is invalid".into()))?;
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    let resolved = base.join(raw).map_err(|_| {
        HelmError::InvalidIndex(format!(
            "Chart \"{chart_name}\" version \"{version}\" has an invalid download URL"
        ))
    })?;
    if resolved.scheme() != base.scheme()
        || resolved.host() != base.host()
        || resolved.port_or_known_default() != base.port_or_known_default()
    {
        return Err(HelmError::InvalidIndex(format!(
            "Chart \"{chart_name}\" version \"{version}\" has a relative download URL \
             that points at a different host"
        )));
    }
    Ok(resolved.to_string())
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
        let versions = list_versions(INDEX, IndexRepo::client_supplied(REPO), "demo").unwrap();
        assert_eq!(versions, vec!["2.0.0", "1.0.0"]);
    }

    #[test]
    fn resolves_absolute_and_relative_urls() {
        assert_eq!(
            resolve_chart_url(INDEX, IndexRepo::client_supplied(REPO), "demo", "2.0.0").unwrap(),
            "https://cdn.example.com/demo-2.0.0.tgz"
        );
        assert_eq!(
            resolve_chart_url(INDEX, IndexRepo::client_supplied(REPO), "demo", "1.0.0").unwrap(),
            "https://repo.example.com/stable/charts/demo-1.0.0.tgz"
        );
    }

    fn index_with_url(raw_url: &str) -> String {
        format!(
            "apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.0.0\n      urls: [\"{raw_url}\"]\n"
        )
    }

    /// RFC 3986 reference resolution, matching Helm's own `repo.ResolveReferenceURL`.
    /// Upstream helmoci concatenates strings and would keep the "/stable" segment.
    #[test]
    fn root_relative_urls_resolve_against_the_repository_root() {
        assert_eq!(
            resolve_chart_url(
                &index_with_url("/charts/demo-1.0.0.tgz"),
                IndexRepo::client_supplied(REPO),
                "demo",
                "1.0.0"
            )
            .unwrap(),
            "https://repo.example.com/charts/demo-1.0.0.tgz"
        );
    }

    #[test]
    fn scheme_relative_urls_never_change_hosts() {
        // The URL parser strips leading spaces and embedded tabs, so a check on the
        // raw string alone would not catch every one of these.
        for raw_url in [
            "//cdn.example/demo-1.0.0.tgz",
            "   //cdn.example/demo-1.0.0.tgz",
            "/\t/cdn.example/demo-1.0.0.tgz",
        ] {
            let error = resolve_chart_url(
                &index_with_url(raw_url),
                IndexRepo::client_supplied(REPO),
                "demo",
                "1.0.0",
            )
            .expect_err(raw_url);
            let HelmError::InvalidIndex(message) = &error else {
                panic!("wrong variant for {raw_url}: {error:?}");
            };
            assert!(!message.contains("cdn.example"), "{message}");
        }
    }

    #[test]
    fn relative_urls_may_still_traverse_within_the_repository_host() {
        assert_eq!(
            resolve_chart_url(
                &index_with_url("../charts/demo-1.0.0.tgz"),
                IndexRepo::client_supplied(REPO),
                "demo",
                "1.0.0"
            )
            .unwrap(),
            "https://repo.example.com/charts/demo-1.0.0.tgz"
        );
    }

    #[test]
    fn missing_chart_lists_available() {
        let err = list_versions(INDEX, IndexRepo::client_supplied(REPO), "nope").unwrap_err();
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
        let err = resolve_chart_url(INDEX, IndexRepo::client_supplied(REPO), "demo", "9.9.9")
            .unwrap_err();
        assert!(matches!(err, HelmError::NotFound(_)));
    }

    #[test]
    fn invalid_yaml_and_missing_entries_are_invalid_index() {
        assert!(matches!(
            list_versions(": not yaml [", IndexRepo::client_supplied(REPO), "demo").unwrap_err(),
            HelmError::InvalidIndex(_)
        ));
        assert!(matches!(
            list_versions("apiVersion: v1", IndexRepo::client_supplied(REPO), "demo").unwrap_err(),
            HelmError::InvalidIndex(_)
        ));
    }

    const SECRET_REPO: &str =
        "https://USER_SENTINEL:PASSWORD_SENTINEL@repo.example/stable?token=QUERY_SENTINEL";

    fn repo_errors(repo: IndexRepo<'_>) -> Vec<HelmError> {
        vec![
            list_versions(": bad [", repo, "demo").unwrap_err(),
            list_versions("entries: {}", repo, "CHART_HINT").unwrap_err(),
            resolve_chart_url(INDEX, repo, "demo", "VERSION_HINT").unwrap_err(),
            resolve_chart_url(
                "entries:\n  demo:\n    - name: demo\n      version: 1.0.0\n",
                repo,
                "demo",
                "1.0.0",
            )
            .unwrap_err(),
        ]
    }

    #[test]
    fn index_errors_never_include_repository_credentials_or_query() {
        for repo in [
            IndexRepo::client_supplied(SECRET_REPO),
            IndexRepo::hidden(SECRET_REPO),
        ] {
            for error in repo_errors(repo) {
                let message = error.to_string();
                for secret in ["USER_SENTINEL", "PASSWORD_SENTINEL", "QUERY_SENTINEL"] {
                    assert!(!message.contains(secret), "{message}");
                }
                assert!(!message.contains('@'), "{message}");
                assert!(!message.contains('?'), "{message}");
            }
        }
    }

    /// A host-path client wrote the repository host into its own reference, so naming
    /// the sanitized repository back tells it nothing it did not supply — and tells an
    /// operator reading the response exactly which repository failed.
    #[test]
    fn client_supplied_index_errors_name_the_sanitized_repository() {
        for error in repo_errors(IndexRepo::client_supplied(SECRET_REPO)) {
            let message = error.to_string();
            assert!(
                message.contains("https://repo.example/stable"),
                "message does not name the repository: {message}"
            );
        }
    }

    /// An alias exists to hide its upstream, which may be an internal repository. Its
    /// origin, port and path must never reach a client.
    #[test]
    fn aliased_index_errors_never_name_the_repository() {
        for error in repo_errors(IndexRepo::hidden(SECRET_REPO)) {
            let message = error.to_string();
            for leak in ["repo.example", "/stable", "https://", "http://"] {
                assert!(!message.contains(leak), "leaked {leak:?}: {message}");
            }
        }
    }

    #[test]
    fn index_errors_omit_an_unparseable_repository_entirely() {
        let error =
            list_versions(": bad [", IndexRepo::client_supplied("not a url"), "demo").unwrap_err();

        assert_eq!(
            error.to_string(),
            "Upstream did not return a valid Helm index.yaml. \
             Check that the path maps to a classic Helm repo."
        );
    }
}
