use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

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
