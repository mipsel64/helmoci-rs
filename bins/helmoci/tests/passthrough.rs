mod common;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use futures::StreamExt;
use helmoci::gcp::GcpTokenProvider;
use helmoci_core::oci::Digest;
use http_body_util::BodyExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::util::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

struct NoAuthHeader;

impl Match for NoAuthHeader {
    fn matches(&self, request: &Request) -> bool {
        !request.headers.contains_key("authorization")
    }
}

const MANIFEST_BODY: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#;
/// The OCI spec makes a manifest's top-level `mediaType` optional (ghcr.io omits it).
const MANIFEST_WITHOUT_MEDIA_TYPE: &str = r#"{"schemaVersion":2,"config":{},"layers":[]}"#;
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// Mirrors `passthrough::MAX_MANIFEST_BYTES` / `MAX_TAG_LIST_BYTES`.
const MANIFEST_LIMIT: usize = 4 * 1024 * 1024;

fn registry_host(server: &MockServer) -> String {
    server.uri().trim_start_matches("http://").to_string()
}

fn cfg(server: &MockServer, store: bool) -> String {
    format!(
        concat!(
            "storage:\n  type: memory\n",
            "aliases:\n",
            "  acme:\n",
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
            "  acme:\n",
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
            "  acme:\n",
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
            // These tests are about rejecting escapes before any ADC contact, not
            // about who may read a credentialed upstream.
            "allow_public_private_upstreams: true\n",
            "aliases:\n",
            "  acme:\n",
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

/// A single GET manifest mock for `latest` with an explicit response media type.
async fn mount_manifest(server: &MockServer, body: &str, content_type: &str, hits: u64) {
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, content_type))
        .expect(hits)
        .mount(server)
        .await;
}

/// A GET whose body is read separately, so a mid-stream failure is observable
/// instead of being unwrapped away.
async fn send_streaming(app: &Router, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(path)
                .header("host", "proxy.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Bytes delivered before the body ended, and whether it ended in an error.
async fn drain_body(response: axum::response::Response) -> (usize, bool) {
    let mut data = response.into_body().into_data_stream();
    let mut delivered = 0;
    while let Some(frame) = data.next().await {
        match frame {
            Ok(bytes) => delivered += bytes.len(),
            Err(_) => return (delivered, true),
        }
    }
    (delivered, false)
}

fn manifest_with_media_type(media_type: &str) -> String {
    format!(
        r#"{{"schemaVersion":2,"mediaType":{},"config":{{}},"layers":[]}}"#,
        serde_json::to_string(media_type).unwrap()
    )
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
        common::send(&app, "GET", "/v2/acme/app/manifests/1.0.0", "proxy.test").await;
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
            common::send(&app, "GET", "/v2/acme/app/manifests/1.0.0", "proxy.test").await;
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
            common::send(&app, "GET", "/v2/acme/app/manifests/1.0.0", "proxy.test").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, body) = common::send(
            &app,
            "GET",
            &format!("/v2/acme/app/blobs/{blob_digest}"),
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
        common::send(&app, "GET", "/v2/acme/app/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["link"], "</v2/acme/app/tags/list?n=1>; rel=next");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["name"], "acme/app");
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
        &format!("/v2/acme/app/blobs/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, blob_body.as_bytes());

    let (status, _, body) = common::send(
        &app,
        "GET",
        &format!("/v2/acme/app/manifests/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["errors"][0]["code"], "MANIFEST_UNKNOWN");
    server.verify().await;
}

/// A backend that cannot persist attributes (local filesystem) stores no content
/// type, and a by-digest pull carries no tag pointer to supply one either. A
/// `mediaType`-less manifest must still be served from that cache: the bytes are
/// an OCI image manifest and nothing else can be inferred from them.
#[tokio::test]
async fn cached_manifest_without_media_type_is_served_by_digest_from_a_metadata_less_backend() {
    let server = MockServer::start().await;
    let digest = Digest::sha256(MANIFEST_WITHOUT_MEDIA_TYPE.as_bytes());
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/manifests/{digest}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(MANIFEST_WITHOUT_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&local_cfg(&server));

    // The upstream mock allows a single hit: the second pull comes from storage.
    for round in 0..2 {
        let (status, headers, body) = common::send(
            &app,
            "GET",
            &format!("/v2/acme/app/manifests/{digest}"),
            "proxy.test",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "round {round}: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body, MANIFEST_WITHOUT_MEDIA_TYPE.as_bytes());
        assert_eq!(headers["content-type"], OCI_MANIFEST_MEDIA_TYPE, "{round}");
        assert_eq!(headers["docker-content-digest"], digest.as_str(), "{round}");
    }
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
        "/v2/acme/%2E%2E/%2E%2E/private/manifests/latest",
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
async fn encoded_backslash_manifest_escape_is_rejected_before_registry_or_adc_contact() {
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
        "/v2/acme/app/manifests/..%5C..%5C..%5Cprivate%5Cmanifests%5Clatest",
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
            "/v2/acme/app/manifests/latest",
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
async fn same_origin_absolute_tag_link_is_rewritten_to_proxy_relative_path() {
    let server = MockServer::start().await;
    let link = format!(
        "<{}/v2/up/charts/app/tags/list?n=1>; rel=next",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", link.as_str())
                .set_body_json(serde_json::json!({"name":"up/charts/app","tags":["1"]})),
        )
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, _) =
        common::send(&app, "GET", "/v2/acme/app/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["link"], "</v2/acme/app/tags/list?n=1>; rel=next");
}

#[tokio::test]
async fn repeated_upstream_tag_link_fields_are_omitted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("link", "</v2/up/charts/app/tags/list?n=1>; rel=next")
                .append_header(
                    "link",
                    "<https://foreign.example/v2/up/charts/app/tags/list?n=2>; rel=next",
                )
                .set_body_json(serde_json::json!({"name":"up/charts/app","tags":["1"]})),
        )
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, _) =
        common::send(&app, "GET", "/v2/acme/app/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("link").is_none());
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

    let (status, headers, body) =
        common::send(&app, "GET", "/v2/acme/app/manifests/latest", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, DOCKER_LIST.as_bytes());
    assert_eq!(
        headers["content-type"],
        "application/vnd.docker.distribution.manifest.list.v2+json"
    );
}

/// `max_chart_bytes` caps charts, not the OCI documents: tightening it must not
/// break manifest or tag-list pass-through (they have their own bound).
#[tokio::test]
async fn manifest_and_tags_are_not_bounded_by_the_chart_limit() {
    let server = MockServer::start().await;
    mount_manifest(&server, MANIFEST_BODY, OCI_MANIFEST_MEDIA_TYPE, 1).await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name":"up/charts/app", "tags":["much-longer-than-ten-bytes"]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&cfg_with_limit(&server, 10));

    for path in ["/v2/acme/app/manifests/latest", "/v2/acme/app/tags/list"] {
        let (status, _, body) = common::send(&app, "GET", path, "proxy.test").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{path}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn oversized_manifest_and_tag_list_bodies_are_rejected() {
    let server = MockServer::start().await;
    let oversized = vec![b'a'; MANIFEST_LIMIT + 1];
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(oversized.clone(), OCI_MANIFEST_MEDIA_TYPE),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(oversized, "application/json"))
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, true));

    for path in ["/v2/acme/app/manifests/latest", "/v2/acme/app/tags/list"] {
        let (status, _, body) = common::send(&app, "GET", path, "proxy.test").await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["errors"][0]["code"],
            "DENIED"
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn cached_manifest_respects_size_limit_without_contacting_upstream() {
    let server = MockServer::start().await;
    let oversized = vec![b'a'; MANIFEST_LIMIT + 1];
    let digest = Digest::sha256(&oversized);
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/manifests/{digest}")))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let (app, state) = common::app_with_state(&cfg(&server, true));
    state
        .storage
        .put_blob(
            &digest,
            OCI_MANIFEST_MEDIA_TYPE,
            bytes::Bytes::from(oversized),
        )
        .await
        .unwrap();

    let (status, _, _) = common::send(
        &app,
        "GET",
        &format!("/v2/acme/app/manifests/{digest}"),
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
        &format!("/v2/acme/app/blobs/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected.as_bytes());
    server.verify().await;
}

/// A cached blob too large to buffer is hashed as it streams, one chunk behind.
/// The mismatch is only knowable after the last byte, so there is no clean
/// fallback (the upstream is never contacted); instead the final chunk is never
/// emitted, so the body ends in an error short of the `Content-Length` it
/// promised rather than passing corrupt bytes off as the digest asked for.
#[tokio::test]
async fn corrupt_large_cached_blob_ends_short_instead_of_being_served() {
    let server = MockServer::start().await;
    let expected = vec![b'z'; 2 * 1024 * 1024];
    let digest = Digest::sha256(&expected);
    // Same length as the real blob, so only hashing can catch it.
    let mut corrupt = expected.clone();
    corrupt[0] = b'a';
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(expected.clone()))
        .expect(0)
        .mount(&server)
        .await;
    let (app, state) = common::app_with_state(&cfg(&server, true));
    state
        .storage
        .put_blob(
            &digest,
            "application/octet-stream",
            bytes::Bytes::from(corrupt),
        )
        .await
        .unwrap();

    let response = send_streaming(&app, &format!("/v2/acme/app/blobs/{digest}")).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-length"],
        expected.len().to_string()
    );
    let (delivered, failed) = drain_body(response).await;
    assert!(
        failed,
        "a corrupt cached blob must not stream out as the requested digest"
    );
    assert!(
        delivered < expected.len(),
        "the body must end short of Content-Length, or a client may accept it as complete"
    );
    server.verify().await;
}

/// The companion of the corruption test: a valid large cached blob still streams
/// through whole.
#[tokio::test]
async fn valid_large_cached_blob_streams_through_verification() {
    let server = MockServer::start().await;
    let expected = vec![b'z'; 2 * 1024 * 1024];
    let digest = Digest::sha256(&expected);
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let (app, state) = common::app_with_state(&cfg(&server, true));
    state
        .storage
        .put_blob(
            &digest,
            "application/octet-stream",
            bytes::Bytes::from(expected.clone()),
        )
        .await
        .unwrap();

    let response = send_streaming(&app, &format!("/v2/acme/app/blobs/{digest}")).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, expected);
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
            common::send(&app, "GET", "/v2/acme/app/tags/list", "proxy.test").await;
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

    let (status, _, _) =
        common::send(&app, "GET", "/v2/acme/app/manifests/latest", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    server.verify().await;
}

/// A manifest `mediaType` reaches a response header, so a control byte inside it
/// used to panic the request task instead of erroring.
#[tokio::test]
async fn poisoned_manifest_media_type_is_rejected_without_panicking() {
    for media_type in [
        "application/vnd.oci.image.manifest.v1+json;\u{1}",
        "application/vnd.oci.image.manifest.v1+json\u{7f}",
        "application/vnd.oci.image.manifest.v1+json; charset=\"un\u{7f}quoted\"",
    ] {
        let server = MockServer::start().await;
        let body = manifest_with_media_type(media_type);
        mount_manifest(&server, &body, OCI_MANIFEST_MEDIA_TYPE, 2).await;
        let app = common::app(&cfg(&server, true));

        // Twice: a poisoned value must never be persisted and re-served either.
        for _ in 0..2 {
            let (status, headers, body) =
                common::send(&app, "GET", "/v2/acme/app/manifests/latest", "proxy.test").await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{media_type:?}");
            assert_eq!(headers["content-type"], "application/json");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["errors"][0]["code"],
                "DENIED"
            );
        }
        server.verify().await;
    }
}

/// A parameterized media type is legal; it must be normalized so the cache can
/// match it on later pulls.
#[tokio::test]
async fn parameterized_manifest_media_type_is_normalized_and_cached() {
    let server = MockServer::start().await;
    let body =
        manifest_with_media_type("application/vnd.oci.image.manifest.v1+json; charset=utf-8");
    mount_manifest(
        &server,
        &body,
        "application/vnd.oci.image.manifest.v1+json; charset=utf-8",
        1,
    )
    .await;
    let app = common::app(&cfg(&server, true));

    for round in 0..2 {
        let (status, headers, got) =
            common::send(&app, "GET", "/v2/acme/app/manifests/latest", "proxy.test").await;
        assert_eq!(status, StatusCode::OK, "round {round}");
        assert_eq!(headers["content-type"], OCI_MANIFEST_MEDIA_TYPE);
        assert_eq!(got, body.as_bytes());
    }
    server.verify().await;
}

#[tokio::test]
async fn manifest_without_media_type_falls_back_to_the_response_content_type() {
    let server = MockServer::start().await;
    mount_manifest(
        &server,
        MANIFEST_WITHOUT_MEDIA_TYPE,
        OCI_MANIFEST_MEDIA_TYPE,
        1,
    )
    .await;
    Mock::given(method("HEAD"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("content-type", OCI_MANIFEST_MEDIA_TYPE),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, true));

    let (head_status, upstream_head_headers, head_body) =
        common::send(&app, "HEAD", "/v2/acme/app/manifests/latest", "proxy.test").await;
    assert_eq!(head_status, StatusCode::OK);
    assert!(head_body.is_empty());

    // Second GET is served from storage: the upstream GET mock expects one hit.
    for round in 0..2 {
        let (status, headers, body) =
            common::send(&app, "GET", "/v2/acme/app/manifests/latest", "proxy.test").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "round {round}: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body, MANIFEST_WITHOUT_MEDIA_TYPE.as_bytes());
        assert_eq!(headers["content-type"], OCI_MANIFEST_MEDIA_TYPE);
        assert_eq!(
            headers["content-type"], upstream_head_headers["content-type"],
            "HEAD and GET must agree"
        );
    }

    let (status, cached_head_headers, body) =
        common::send(&app, "HEAD", "/v2/acme/app/manifests/latest", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
    assert_eq!(
        cached_head_headers["content-type"], upstream_head_headers["content-type"],
        "cached HEAD must agree with upstream HEAD"
    );
    assert_eq!(
        cached_head_headers["content-length"],
        MANIFEST_WITHOUT_MEDIA_TYPE.len().to_string()
    );
    server.verify().await;
}

#[tokio::test]
async fn manifest_without_media_type_or_manifest_content_type_is_rejected() {
    let server = MockServer::start().await;
    mount_manifest(&server, MANIFEST_WITHOUT_MEDIA_TYPE, "application/json", 1).await;
    let app = common::app(&cfg(&server, false));

    let (status, _, body) =
        common::send(&app, "GET", "/v2/acme/app/manifests/latest", "proxy.test").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["errors"][0]["code"],
        "DENIED"
    );
    server.verify().await;
}

#[tokio::test]
async fn head_manifest_only_forwards_a_verifiable_upstream_digest() {
    let server = MockServer::start().await;
    let digest = Digest::sha256(MANIFEST_BODY.as_bytes());
    let other = Digest::sha256(b"other");
    Mock::given(method("HEAD"))
        .and(path("/v2/up/charts/app/manifests/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", OCI_MANIFEST_MEDIA_TYPE)
                .insert_header("docker-content-digest", "not-a-digest"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path(format!("/v2/up/charts/app/manifests/{digest}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", OCI_MANIFEST_MEDIA_TYPE)
                .insert_header("docker-content-digest", other.as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, _) =
        common::send(&app, "HEAD", "/v2/acme/app/manifests/latest", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get("docker-content-digest").is_none(),
        "an unparsable upstream digest must not be forwarded"
    );

    let (status, _, _) = common::send(
        &app,
        "HEAD",
        &format!("/v2/acme/app/manifests/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "a digest request answered with a different digest is a lying upstream"
    );
    server.verify().await;
}

#[tokio::test]
async fn chunked_blob_is_cached_under_store_true() {
    let server = MockServer::start().await;
    let blob_body = "chunked-blob-bytes";
    let digest = Digest::sha256(blob_body.as_bytes());
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/blobs/{digest}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("transfer-encoding", "chunked")
                .set_body_string(blob_body),
        )
        .expect(1)
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, true));

    for round in 0..2 {
        let (status, _, body) = common::send(
            &app,
            "GET",
            &format!("/v2/acme/app/blobs/{digest}"),
            "proxy.test",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "round {round}");
        assert_eq!(body, blob_body.as_bytes());
    }
    server.verify().await;
}

/// Blobs above the cache bound stream through intact (advertised or chunked) and
/// are not cached, so every pull hits the upstream.
#[tokio::test]
async fn oversized_blobs_stream_through_uncached() {
    let blob_body = "0123456789abcdefghijklmnopqrstuvwxyz";
    let digest = Digest::sha256(blob_body.as_bytes());
    for chunked in [false, true] {
        let server = MockServer::start().await;
        let mut template = ResponseTemplate::new(200);
        if chunked {
            template = template.insert_header("transfer-encoding", "chunked");
        }
        Mock::given(method("GET"))
            .and(path(format!("/v2/up/charts/app/blobs/{digest}")))
            .respond_with(template.set_body_string(blob_body))
            .expect(2)
            .mount(&server)
            .await;
        let app = common::app(&cfg_with_limit(&server, 10));

        for round in 0..2 {
            let (status, _, body) = common::send(
                &app,
                "GET",
                &format!("/v2/acme/app/blobs/{digest}"),
                "proxy.test",
            )
            .await;
            assert_eq!(status, StatusCode::OK, "chunked={chunked} round {round}");
            assert_eq!(body, blob_body.as_bytes(), "chunked={chunked}");
        }
        server.verify().await;
    }
}

/// Cached blobs stream out of the content-addressed store instead of being
/// buffered, so the chart cap does not gate them either.
#[tokio::test]
async fn large_cached_blob_is_served_from_storage_without_buffering() {
    let server = MockServer::start().await;
    let blob_body = vec![b'z'; 2 * 1024 * 1024];
    let digest = Digest::sha256(&blob_body);
    Mock::given(method("GET"))
        .and(path(format!("/v2/up/charts/app/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(blob_body.clone()))
        .expect(0)
        .mount(&server)
        .await;
    let (app, state) = common::app_with_state(&cfg_with_limit(&server, 10));
    state
        .storage
        .put_blob(
            &digest,
            "application/octet-stream",
            bytes::Bytes::from(blob_body.clone()),
        )
        .await
        .unwrap();

    let (status, headers, body) = common::send(
        &app,
        "GET",
        &format!("/v2/acme/app/blobs/{digest}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), blob_body.len());
    assert_eq!(body, blob_body);
    assert_eq!(headers["content-length"], blob_body.len().to_string());
    server.verify().await;
}

#[tokio::test]
async fn multi_value_tag_link_field_keeps_only_the_next_relation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    "</v2/up/charts/app/tags/list?n=2&last=b>; rel=\"next\", \
                     <https://foreign.example/v2/up/charts/app/tags/list?n=2>; rel=\"prev\"",
                )
                .set_body_json(serde_json::json!({"name":"up/charts/app","tags":["1"]})),
        )
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, _) =
        common::send(&app, "GET", "/v2/acme/app/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["link"],
        "</v2/acme/app/tags/list?n=2&last=b>; rel=\"next\""
    );
}

#[tokio::test]
async fn cross_origin_next_tag_link_is_dropped_even_beside_a_safe_link() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/up/charts/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    "<https://foreign.example/v2/up/charts/app/tags/list?n=2>; rel=\"next\", \
                     </v2/up/charts/app/tags/list?n=0>; rel=\"prev\"",
                )
                .set_body_json(serde_json::json!({"name":"up/charts/app","tags":["1"]})),
        )
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server, false));

    let (status, headers, _) =
        common::send(&app, "GET", "/v2/acme/app/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("link").is_none());
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
        common::send(&app, "GET", "/v2/acme/app/tags/list", "proxy.test").await;
    let (head_status, head_headers, head_body) =
        common::send(&app, "HEAD", "/v2/acme/app/tags/list", "proxy.test").await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(head_status, StatusCode::OK);
    assert!(head_body.is_empty());
    for name in ["content-type", "content-length", "etag"] {
        assert_eq!(head_headers[name], get_headers[name], "{name}");
    }
    assert_eq!(get_headers["content-length"], get_body.len().to_string());
    server.verify().await;
}
