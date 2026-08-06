use crate::classic;
use crate::error::AppError;
use crate::passthrough;
use crate::state::SharedState;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use helmoci_core::oci::route::{OciRoute, parse_oci_path};
use helmoci_core::resolver::{Resolved, resolve_name};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A 253-byte hostname plus `:65535`.
const MAX_PROXY_HOST_LEN: usize = 259;

pub fn build_router(state: SharedState) -> Router {
    let _ = crate::metrics::handle();
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_endpoint))
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(oci_dispatch)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::require_pull_auth,
        ))
        .layer(axum::middleware::from_fn(crate::metrics::record_http))
        .with_state(state)
}

async fn home() -> Html<&'static str> {
    Html(include_str!("home.html"))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics_endpoint() -> String {
    crate::metrics::handle().render()
}

pub fn invalid_path_message(name: &str) -> String {
    format!(
        "Invalid OCI path {name:?}. Use a configured alias or a public host and chart name: \
         oci://<proxy>/<host>/<repo-path>/<chart> (e.g. argoproj.github.io/argo-helm/argo-cd). \
         Localhost and raw IP addresses are not allowed."
    )
}

const INVALID_HOST_MESSAGE: &str = "Invalid Host header. helmoci uses it as the proxy host in rewritten oci:// dependency URLs \
     and as a cache key segment, so it must be a host[:port] value such as charts.example.com, \
     charts.example.com:8443, 127.0.0.1:8080, or [::1]:8080.";

fn invalid_host() -> AppError {
    AppError::NameInvalid(INVALID_HOST_MESSAGE.into())
}

fn unsupported_method() -> AppError {
    AppError::Unsupported("only GET/HEAD are supported".into())
}

async fn method_not_allowed() -> Response {
    unsupported_method().into_response()
}

fn header_host(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// HTTP/2 carries the authority in the URI instead of a `Host` header.
fn uri_host(uri: &Uri) -> Option<String> {
    let host = uri.host()?;
    Some(match uri.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn is_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn is_valid_port(port: &str) -> bool {
    port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port > 0)
}

/// Split `host[:port]`, keeping IPv6 literals bracketed.
fn split_host_port(value: &str) -> Option<(&str, Option<&str>, bool)> {
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let port = match &rest[end + 1..] {
            "" => None,
            remainder => Some(remainder.strip_prefix(':')?),
        };
        return Some((&rest[..end], port, true));
    }
    match value.split_once(':') {
        Some((host, port)) => Some((host, Some(port), false)),
        None => Some((value, None, false)),
    }
}

/// Canonical `host[:port]` that is safe to use as a storage key segment.
fn normalize_proxy_host(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > MAX_PROXY_HOST_LEN {
        return None;
    }
    let lowercased = value.to_ascii_lowercase();
    let (host, port, bracketed) = split_host_port(&lowercased)?;
    let host_ok = if bracketed {
        host.parse::<Ipv6Addr>().is_ok()
    } else {
        host.parse::<Ipv4Addr>().is_ok() || is_dns_name(host)
    };
    if !host_ok || port.is_some_and(|port| !is_valid_port(port)) {
        return None;
    }
    Some(lowercased)
}

/// Host clients should use for rewritten oci:// dependency URLs and cache keys.
fn proxy_host_from(req: &Request<Body>) -> Option<String> {
    let candidate = match header_host(req.headers()) {
        Some(host) => host.to_string(),
        None => uri_host(req.uri())?,
    };
    normalize_proxy_host(&candidate)
}

fn api_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .body(Body::empty())
        .expect("static headers are valid")
}

async fn oci_dispatch(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let path = req.uri().path().to_string();
    if path != "/v2" && !path.starts_with("/v2/") {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    let head_only = match *req.method() {
        Method::GET => false,
        Method::HEAD => true,
        _ => return unsupported_method().into_response(),
    };
    let Some(proxy_host) = proxy_host_from(&req) else {
        return invalid_host().into_response();
    };
    let query = req.uri().query().map(str::to_string);
    let accept = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let result = match parse_oci_path(&path) {
        OciRoute::Api => Ok(api_response()),
        OciRoute::Manifest { name, reference } => {
            manifest_entry(&state, &proxy_host, &name, &reference, head_only, accept).await
        }
        OciRoute::Blob { name, digest } => blob_entry(&state, &name, &digest, head_only).await,
        OciRoute::Tags { name } => tags_entry(&state, &name, query.as_deref(), head_only).await,
        OciRoute::NotFound => Err(AppError::NameUnknown("unknown registry path".into())),
    };
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn manifest_entry(
    state: &SharedState,
    proxy_host: &str,
    name: &str,
    reference: &str,
    head_only: bool,
    accept: Option<String>,
) -> Result<Response, AppError> {
    match resolve_name(name, &state.cfg.aliases) {
        Some(Resolved::Classic(chart)) => {
            classic::manifest(state, proxy_host, chart, reference, head_only).await
        }
        Some(Resolved::Oci(target)) => {
            passthrough::manifest(state, proxy_host, target, reference, head_only, accept).await
        }
        None => Err(AppError::NameUnknown(invalid_path_message(name))),
    }
}

async fn blob_entry(
    state: &SharedState,
    name: &str,
    digest: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    match resolve_name(name, &state.cfg.aliases) {
        Some(Resolved::Classic(_)) => classic::blob(state, digest, head_only).await,
        Some(Resolved::Oci(target)) => passthrough::blob(state, target, digest, head_only).await,
        None => Err(AppError::NameUnknown(invalid_path_message(name))),
    }
}

async fn tags_entry(
    state: &SharedState,
    name: &str,
    query: Option<&str>,
    head_only: bool,
) -> Result<Response, AppError> {
    match resolve_name(name, &state.cfg.aliases) {
        Some(Resolved::Classic(chart)) => classic::tags(state, chart, query, head_only).await,
        Some(Resolved::Oci(target)) => passthrough::tags(state, target, query, head_only).await,
        None => Err(AppError::NameUnknown(invalid_path_message(name))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, host: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        builder.body(Body::empty()).expect("valid test request")
    }

    #[test]
    fn host_header_wins_over_the_uri_authority() {
        let req = request("http://uri.example:1234/v2/", Some("header.example:8080"));

        assert_eq!(
            proxy_host_from(&req).as_deref(),
            Some("header.example:8080")
        );
    }

    #[test]
    fn falls_back_to_the_uri_authority_when_no_host_header_exists() {
        assert_eq!(
            proxy_host_from(&request("http://h2.example:9443/v2/", None)).as_deref(),
            Some("h2.example:9443")
        );
        assert_eq!(
            proxy_host_from(&request("http://h2.example/v2/", None)).as_deref(),
            Some("h2.example")
        );
        assert_eq!(
            proxy_host_from(&request("http://[::1]:9443/v2/", None)).as_deref(),
            Some("[::1]:9443")
        );
    }

    #[test]
    fn rejects_requests_without_any_host_information() {
        assert_eq!(proxy_host_from(&request("/v2/", None)), None);
        assert_eq!(proxy_host_from(&request("/v2/", Some("   "))), None);
    }

    #[test]
    fn accepts_local_ip_and_public_hosts_and_lowercases_them() {
        for (value, expected) in [
            ("proxy.test", "proxy.test"),
            ("PROXY.Test:8443", "proxy.test:8443"),
            ("127.0.0.1", "127.0.0.1"),
            ("127.0.0.1:8080", "127.0.0.1:8080"),
            ("localhost", "localhost"),
            ("localhost:8080", "localhost:8080"),
            ("[::1]", "[::1]"),
            ("[::1]:8080", "[::1]:8080"),
            ("a-b.c-d.example:65535", "a-b.c-d.example:65535"),
        ] {
            assert_eq!(
                normalize_proxy_host(value).as_deref(),
                Some(expected),
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_host_values_that_are_not_a_host_port() {
        let long_label = "a".repeat(64);
        let long_host = format!("{}.example", "a".repeat(250));
        for value in [
            "",
            ".",
            "..",
            "../evil",
            "proxy.test/../evil",
            "proxy.test/nested",
            "has space.example",
            "under_score.example",
            "-bad.example",
            "bad-.example",
            "a..b.example",
            "proxy.test:",
            "proxy.test:0",
            "proxy.test:70000",
            "proxy.test:123456",
            "proxy.test:8080:9090",
            "proxy.test:80a",
            "user@proxy.test",
            "[::1",
            "[not-an-ip]",
            "[::1]8080",
            "[::1]:0",
            long_label.as_str(),
            long_host.as_str(),
        ] {
            assert_eq!(normalize_proxy_host(value), None, "{value:?}");
        }
    }
}
