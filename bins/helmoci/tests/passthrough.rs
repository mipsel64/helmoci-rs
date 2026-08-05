mod common;

use async_trait::async_trait;
use axum::http::StatusCode;
use helmoci::gcp::GcpTokenProvider;
use helmoci_core::oci::Digest;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

struct NoAuthHeader;

impl Match for NoAuthHeader {
    fn matches(&self, request: &Request) -> bool {
        !request.headers.contains_key("authorization")
    }
}

const MANIFEST_BODY: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#;

fn registry_host(server: &MockServer) -> String {
    server.uri().trim_start_matches("http://").to_string()
}

fn cfg(server: &MockServer, store: bool) -> String {
    format!(
        concat!(
            "storage:\n  type: memory\n",
            "aliases:\n",
            "  meteora:\n",
            "    upstream: oci://{host}/up/charts\n",
            "    plain_http: true\n",
            "    store: {store}\n",
        ),
        host = registry_host(server),
        store = store
    )
}

fn local_cfg(server: &MockServer) -> String {
    let dir = tempfile::tempdir().unwrap().keep();
    format!(
        concat!(
            "storage:\n  type: local\n  settings:\n    path: {path}\n",
            "aliases:\n",
            "  meteora:\n",
            "    upstream: oci://{host}/up/charts\n",
            "    plain_http: true\n",
            "    store: true\n",
        ),
        path = dir.display(),
        host = registry_host(server),
    )
}

fn cfg_with_limit(server: &MockServer, limit: u64) -> String {
    format!(
        concat!(
            "storage:\n  type: memory\n",
            "max_chart_bytes: {limit}\n",
            "aliases:\n",
            "  meteora:\n",
            "    upstream: oci://{host}/up/charts\n",
            "    plain_http: true\n",
            "    store: true\n",
        ),
        host = registry_host(server),
        limit = limit,
    )
}

fn gcp_cfg(server: &MockServer) -> String {
    format!(
        concat!(
            "storage:\n  type: memory\n",
            "aliases:\n",
            "  meteora:\n",
            "    upstream: oci://{host}/up/charts\n",
            "    auth: gcp\n",
            "    plain_http: true\n",
        ),
        host = registry_host(server),
    )
}

struct CountingGcp(Arc<AtomicUsize>);

#[async_trait]
impl GcpTokenProvider for CountingGcp {
    async fn access_token(&self) -> Result<String, helmoci::error::AppError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok("should-not-be-requested".to_string())
    }
}

/// 401-without-auth + 200-with-token mocks for one upstream path.
async fn mount_protected(server: &MockServer, upstream_path: &str, body: &str, authed_hits: u64) {
    Mock::given(method("GET"))
        .and(path(upstream_path))
        .and(NoAuthHeader)
        .respond_with(
            ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!(
                    "Bearer realm=\"{}/token\",service=\"reg.test\"",
                    server.uri()
                )
                .as_str(),
            ),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(upstream_path))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                .set_body_string(body),
        )
        .expect(authed_hits)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "test-token"
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn proxies_manifest_with_token_dance() {
    let server = MockServer::start().await;
    mount_protected(
        &server,
        "/v2/up/charts/app/manifests/1.0.0",
        MANIFEST_BODY,
        1,
    )
    .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, body) =
        common::send(&app, "GET", "/v2/meteora/app/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, MANIFEST_BODY.as_bytes());
    assert_eq!(
        headers["Docker-Content-Digest"].to_str().unwrap(),
        Digest::sha256(MANIFEST_BODY.as_bytes()).as_str()
    );
}

#[tokio::test]
async fn store_false_proxies_every_pull() {
    let server = MockServer::start().await;
    mount_protected(
        &server,
        "/v2/up/charts/app/manifests/1.0.0",
        MANIFEST_BODY,
        2,
    )
    .await;
    let app = common::app(&cfg(&server, false));
    for _ in 0..2 {
        let (status, _, _) =
            common::send(&app, "GET", "/v2/meteora/app/manifests/1.0.0", "proxy.test").await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn store_true_caches_manifests_and_blobs() {
    let server = MockServer::start().await;
    mount_protected(
        &server,
        "/v2/up/charts/app/manifests/1.0.0",
        MANIFEST_BODY,
        1,
    )
    .await;
    let blob_body = "blob-bytes";
    let blob_digest = Digest::sha256(blob_body.as_bytes());
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/blobs/{blob_digest}")))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(blob_body))
        .expect(1)
        .mount(&server)
        .await;

    let app = common::app(&cfg(&server, true));
    for _ in 0..2 {
        let (status, _, _) =
            common::send(&app, "GET", "/v2/meteora/app/manifests/1.0.0", "proxy.test").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, body) = common::send(
            &app,
            "GET",
            &format!("/v2/meteora/app/blobs/{blob_digest}"),
            "proxy.test",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, blob_body.as_bytes());
    }
    // .expect(1) on the authed mocks verifies the second round came from storage
}

#[tokio::test]
async fn tags_passthrough_rewrites_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", "</v2/up/charts/app/tags/list?n=1>; rel=next")
                .set_body_json(serde_json::json!({
                    "name": "up/charts/app",
                    "tags": ["1.0.0", "0.9.0"]
                })),
        )
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));
    let (status, headers, body) =
        common::send(&app, "GET", "/v2/meteora/app/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["link"], "</v2/meteora/app/tags/list?n=1>; rel=next");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["name"], "meteora/app");
    assert_eq!(v["tags"], serde_json::json!(["1.0.0", "0.9.0"]));
}

#[tokio::test]
async fn cached_blob_digest_is_not_a_manifest_without_metadata() {
    let server = MockServer::start().await;
    let blob_body = "not-a-manifest";
    let digest = Digest::sha256(blob_body.as_bytes());
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(blob_body))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/manifests/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(MANIFEST_BODY))
        .expect(0)
        .mount(&server)
        .await;
    let app = common::app(&local_cfg(&server));

    let (status, _, body) = common::send(
        &app,
        "GET",
        &format!("/v2/meteora/app/blobs/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, blob_body.as_bytes());

    let (status, _, body) = common::send(
        &app,
        "GET",
        &format!("/v2/meteora/app/manifests/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["errors"][0]["code"], "MANIFEST_UNKNOWN");
    server.verify().await;
}

#[tokio::test]
async fn encoded_alias_escape_is_rejected_before_registry_or_adc_contact() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let app = common::app_with_gcp(&gcp_cfg(&server), Arc::new(CountingGcp(calls.clone())));

    let (status, _, body) = common::send(
        &app,
        "GET",
        "/v2/meteora/%2E%2E/%2E%2E/private/manifests/latest",
        "proxy.test",
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["errors"][0]["code"],
        "NAME_UNKNOWN"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.verify().await;
}

#[tokio::test]
async fn cached_manifest_respects_current_accept_representation() {
    const DOCKER_LIST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[]}"#;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .and(header(
            "accept",
            "application/vnd.oci.image.manifest.v1+json",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(MANIFEST_BODY, "application/vnd.oci.image.manifest.v1+json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .and(header(
            "accept",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            DOCKER_LIST,
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, true));

    for (accept, expected) in [
        ("application/vnd.oci.image.manifest.v1+json", MANIFEST_BODY),
        (
            "application/vnd.docker.distribution.manifest.list.v2+json",
            DOCKER_LIST,
        ),
    ] {
        let (status, _, body) = common::send_with_headers(
            &app,
            "GET",
            "/v2/meteora/app/manifests/latest",
            "proxy.test",
            &[("accept", accept)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected.as_bytes());
    }
    server.verify().await;
}

#[tokio::test]
async fn absolute_tag_link_is_rewritten_to_proxy_relative_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    "<https://registry.example/v2/up/charts/app/tags/list?n=1>; rel=next",
                )
                .set_body_json(serde_json::json!({"name":"up/charts/app","tags":["1"]})),
        )
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, _) =
        common::send(&app, "GET", "/v2/meteora/app/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["link"], "</v2/meteora/app/tags/list?n=1>; rel=next");
}

#[tokio::test]
async fn default_accept_supports_docker_manifest_lists() {
    const DOCKER_LIST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[]}"#;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            DOCKER_LIST,
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ))
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, body) = common::send(
        &app,
        "GET",
        "/v2/meteora/app/manifests/latest",
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, DOCKER_LIST.as_bytes());
    assert_eq!(
        headers["content-type"],
        "application/vnd.docker.distribution.manifest.list.v2+json"
    );
}

#[tokio::test]
async fn buffered_manifest_and_tags_respect_size_limit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(MANIFEST_BODY, "application/vnd.oci.image.manifest.v1+json"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name":"up/charts/app", "tags":["too-long"]
        })))
        .mount(&server)
        .await;
    let app = common::app(&cfg_with_limit(&server, 10));

    for path in [
        "/v2/meteora/app/manifests/latest",
        "/v2/meteora/app/tags/list",
    ] {
        let (status, _, body) = common::send(&app, "GET", path, "proxy.test").await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["errors"][0]["code"],
            "DENIED"
        );
    }
}

#[tokio::test]
async fn cached_manifest_respects_size_limit_without_contacting_upstream() {
    let server = MockServer::start().await;
    let digest = Digest::sha256(MANIFEST_BODY.as_bytes());
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/manifests/{digest}")))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let (app, state) = common::app_with_state(&cfg_with_limit(&server, 10));
    state
        .storage
        .put_blob(
            &digest,
            "application/vnd.oci.image.manifest.v1+json",
            bytes::Bytes::from_static(MANIFEST_BODY.as_bytes()),
        )
        .await
        .unwrap();

    let (status, _, _) = common::send(
        &app,
        "GET",
        &format!("/v2/meteora/app/manifests/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    server.verify().await;
}

#[tokio::test]
async fn corrupt_cached_blob_falls_back_to_verified_upstream_bytes() {
    let server = MockServer::start().await;
    let expected = "good-bytes";
    let digest = Digest::sha256(expected.as_bytes());
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(expected))
        .expect(1)
        .mount(&server)
        .await;
    let (app, state) = common::app_with_state(&cfg(&server, true));
    state
        .storage
        .put_blob(
            &digest,
            "application/octet-stream",
            bytes::Bytes::from_static(b"corrupt"),
        )
        .await
        .unwrap();

    let (status, _, body) = common::send(
        &app,
        "GET",
        &format!("/v2/meteora/app/blobs/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected.as_bytes());
    server.verify().await;
}

#[tokio::test]
async fn invalid_tag_json_is_an_upstream_error() {
    for body in ["not-json", "[]", "\"scalar\""] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/up/charts/app/tags/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let app = common::app(&cfg(&server, false));
        let (status, _, _) =
            common::send(&app, "GET", "/v2/meteora/app/tags/list", "proxy.test").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    }
}

#[tokio::test]
async fn repeated_authenticate_headers_find_bearer_challenge() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .and(NoAuthHeader)
        .respond_with(
            ResponseTemplate::new(401)
                .append_header("www-authenticate", "Basic realm=legacy")
                .append_header(
                    "www-authenticate",
                    format!("Bearer realm=\"{}/token\"", server.uri()),
                ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(MANIFEST_BODY, "application/vnd.oci.image.manifest.v1+json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"token":"test-token"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, _, _) = common::send(
        &app,
        "GET",
        "/v2/meteora/app/manifests/latest",
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    server.verify().await;
}

#[tokio::test]
async fn tag_head_uses_get_representation_metadata() {
    let server = MockServer::start().await;
    let upstream = serde_json::json!({"name":"up/charts/app","tags":["1.0.0"]});
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(upstream))
        .expect(2)
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (get_status, get_headers, get_body) =
        common::send(&app, "GET", "/v2/meteora/app/tags/list", "proxy.test").await;
    let (head_status, head_headers, head_body) =
        common::send(&app, "HEAD", "/v2/meteora/app/tags/list", "proxy.test").await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(head_status, StatusCode::OK);
    assert!(head_body.is_empty());
    for name in ["content-type", "content-length", "etag"] {
        assert_eq!(head_headers[name], get_headers[name], "{name}");
    }
    assert_eq!(get_headers["content-length"], get_body.len().to_string());
    server.verify().await;
}
