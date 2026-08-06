use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

#[derive(Clone, Copy)]
pub(crate) enum UpstreamKind {
    ClassicIndex,
    ClassicChart,
    OciManifest,
    OciBlob,
    OciTags,
    OciToken,
}

impl UpstreamKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ClassicIndex => "classic_index",
            Self::ClassicChart => "classic_chart",
            Self::OciManifest => "oci_manifest",
            Self::OciBlob => "oci_blob",
            Self::OciTags => "oci_tags",
            Self::OciToken => "oci_token",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ProxyKind {
    Manifest,
    Blob,
    Tags,
}

impl ProxyKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Blob => "blob",
            Self::Tags => "tags",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ProxyUpstream {
    Classic,
    Oci,
}

impl ProxyUpstream {
    const fn label(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Oci => "oci",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ProxySource {
    Upstream,
    PersistentCache,
    EphemeralCache,
}

impl ProxySource {
    const fn label(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::PersistentCache => "persistent_cache",
            Self::EphemeralCache => "ephemeral_cache",
        }
    }
}

pub(crate) fn record_proxy_response(kind: ProxyKind, upstream: ProxyUpstream, source: ProxySource) {
    metrics::counter!(
        "helmoci_proxy_responses_total",
        "kind" => kind.label(),
        "upstream" => upstream.label(),
        "source" => source.label(),
    )
    .increment(1);
}

pub(crate) fn record_blob_bytes(upstream: ProxyUpstream, source: ProxySource, bytes: usize) {
    metrics::counter!(
        "helmoci_blob_bytes_served_total",
        "upstream" => upstream.label(),
        "source" => source.label(),
    )
    .increment(bytes as u64);
}

pub fn handle() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("prometheus recorder installs once per process")
        })
        .clone()
}

fn route_kind(path: &str) -> &'static str {
    match path {
        "/" => return "home",
        "/healthz" => return "healthz",
        "/metrics" => return "metrics",
        "/v2" | "/v2/" => return "api",
        _ => {}
    }

    let Some(v2_path) = path.strip_prefix("/v2/") else {
        return "other";
    };
    if v2_path.contains("/manifests/") {
        return "manifest";
    }
    if v2_path.contains("/blobs/") {
        return "blob";
    }
    if v2_path.ends_with("/tags/list") {
        return "tags";
    }
    "other"
}

pub async fn record_http(req: Request<Body>, next: Next) -> Response {
    let route = route_kind(req.uri().path());
    let start = Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    metrics::counter!("helmoci_http_requests_total", "route" => route, "status" => status)
        .increment(1);
    metrics::histogram!("helmoci_http_request_duration_seconds", "route" => route)
        .record(start.elapsed().as_secs_f64());
    response
}
