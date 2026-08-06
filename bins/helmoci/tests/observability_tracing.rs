mod common;

use axum::http::StatusCode;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const MANIFEST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#;

struct NoAuthHeader;

impl Match for NoAuthHeader {
    fn matches(&self, request: &Request) -> bool {
        !request.headers.contains_key("authorization")
    }
}

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn native_tracing_reports_token_redirect_and_cache_events_without_secrets() {
    const REFERENCE: &str = "TRACE_REFERENCE_SENTINEL";
    const TOKEN_QUERY: &str = "TOKEN_QUERY_SENTINEL";
    const TOKEN_REDIRECT_QUERY: &str = "TOKEN_REDIRECT_QUERY_SENTINEL";
    const MANIFEST_REDIRECT_QUERY: &str = "MANIFEST_REDIRECT_QUERY_SENTINEL";
    const TOKEN: &str = "TRACE_BEARER_TOKEN_SENTINEL";
    let server = MockServer::start().await;
    let manifest_path = format!("/v2/up/charts/app/manifests/{REFERENCE}");
    Mock::given(method("GET"))
        .and(path(&manifest_path))
        .and(NoAuthHeader)
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            format!(
                "Bearer realm=\"{}/token-start?client_secret={TOKEN_QUERY}\",service=\"registry-secret-service\"",
                server.uri()
            ),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/token-start"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("/token-final?signature={TOKEN_REDIRECT_QUERY}"),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/token-final"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": TOKEN,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&manifest_path))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("/manifest-final?signature={MANIFEST_REDIRECT_QUERY}"),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/manifest-final"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                .set_body_string(MANIFEST),
        )
        .expect(1)
        .mount(&server)
        .await;

    let output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = output.clone();
    let subscriber = tracing_subscriber::fmt()
        // Every target, not just helmoci's: the sentinel assertions below claim no
        // URL reaches the logs, which a production `RUST_LOG=debug` would test
        // against dependency events too.
        .with_env_filter(EnvFilter::new("debug"))
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_writer(move || SharedWriter(writer_output.clone()))
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    // Under the old `helmoci=debug` filter this was dropped, which is what made
    // the sentinel assertions below unable to say anything about anyone else's
    // events. Note that dependencies logging through the `log` facade are absent
    // for a different reason: no bridge is installed, here or in `main`.
    tracing::debug!(target: "not_helmoci", "dependency target event");
    let cfg = format!(
        concat!(
            "storage:\n  type: memory\n",
            "aliases:\n",
            "  observed:\n",
            "    upstream: oci://{host}/up/charts\n",
            "    plain_http: true\n",
            "    store: true\n",
        ),
        host = server.uri().trim_start_matches("http://"),
    );
    let app = common::app(&cfg);
    for _ in 0..2 {
        let (status, _, body) = common::send(
            &app,
            "GET",
            &format!("/v2/observed/app/manifests/{REFERENCE}"),
            "proxy.test",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }

    let (_, _, metrics) = common::send(&app, "GET", "/metrics", "proxy.test").await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();
    for (kind, expected) in [("oci_manifest", 3), ("oci_token", 2)] {
        let count = metrics
            .lines()
            .find_map(|line| {
                line.strip_prefix("helmoci_upstream_request_duration_seconds_count{")
                    .filter(|sample| sample.contains(&format!(r#"kind="{kind}""#)))?
                    .split_whitespace()
                    .last()?
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or_default();
        assert_eq!(
            count, expected,
            "{kind} requests were not all measured: {metrics}"
        );
    }

    let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("dependency target event"),
        "the filter must cover every target, not just helmoci's: {logs}"
    );
    for event in [
        "OCI cache miss",
        "OCI cache hit",
        "upstream request start",
        "upstream request complete",
        "upstream redirect follow",
        "registry token refresh start",
        "registry token refresh complete",
    ] {
        assert!(logs.contains(event), "missing event {event:?}: {logs}");
    }
    for secret in [
        REFERENCE,
        TOKEN_QUERY,
        TOKEN_REDIRECT_QUERY,
        MANIFEST_REDIRECT_QUERY,
        TOKEN,
        "registry-secret-service",
        "observed/app",
        "up/charts/app",
        server.uri().as_str(),
    ] {
        assert!(!logs.contains(secret), "tracing leaked {secret:?}: {logs}");
        assert!(
            !metrics.contains(secret),
            "metrics leaked {secret:?}: {metrics}"
        );
    }
    for scheme in ["http://", "https://", "oci://"] {
        assert!(!logs.contains(scheme), "tracing leaked a URL: {logs}");
    }
    server.verify().await;
}
