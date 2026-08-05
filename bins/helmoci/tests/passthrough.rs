mod common;

use axum::http::StatusCode;
use helmoci_core::oci::Digest;
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
