mod common;

use axum::http::StatusCode;
use helmoci_core::helm::tgz::testutil::build_chart_tgz;
use helmoci_core::oci::OciManifest;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CHART_YAML: &str = concat!(
    "name: demo\nversion: 1.0.0\ndependencies:\n",
    "  - name: redis\n    version: 1.0.0\n    repository: https://charts.bitnami.com/bitnami\n",
);

fn cfg(server_uri: &str) -> String {
    format!(
        concat!(
            "storage:\n  backend: memory\n",
            "max_chart_bytes: 65536\n",
            "aliases:\n",
            "  test:\n    upstream: {uri}\n    store: true\n",
            "  eph:\n    upstream: {uri}\n    store: false\n",
        ),
        uri = server_uri
    )
}

async fn mount_upstream(server: &MockServer, expect_index: u64, expect_tgz: u64) {
    let index = format!(
        "entries:\n  demo:\n    - name: demo\n      version: 1.0.0\n      urls: [\"{}/demo-1.0.0.tgz\"]\n",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/index.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .expect(expect_index)
        .mount(server)
        .await;
    let tgz = build_chart_tgz(&[("demo/Chart.yaml", CHART_YAML)]);
    Mock::given(method("GET"))
        .and(path("/demo-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
        .expect(expect_tgz)
        .mount(server)
        .await;
}

#[tokio::test]
async fn full_pull_flow_with_dependency_rewrite() {
    let server = MockServer::start().await;
    mount_upstream(&server, 1, 1).await;
    let app = common::app(&cfg(&server.uri()));

    let (status, headers, body) =
        common::send(&app, "GET", "/v2/test/demo/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        headers["Content-Type"],
        "application/vnd.oci.image.manifest.v1+json"
    );
    let manifest_digest = headers["Docker-Content-Digest"]
        .to_str()
        .unwrap()
        .to_string();
    let manifest: OciManifest = serde_json::from_slice(&body).unwrap();

    // config blob
    let cfg_path = format!("/v2/test/demo/blobs/{}", manifest.config.digest);
    let (status, _, config) = common::send(&app, "GET", &cfg_path, "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
    assert_eq!(config["name"], "demo");

    // layer blob: dependency must be rewritten to the proxy host
    let layer_path = format!("/v2/test/demo/blobs/{}", manifest.layers[0].digest);
    let (status, _, layer) = common::send(&app, "GET", &layer_path, "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let layer_text = {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut archive = tar::Archive::new(GzDecoder::new(&layer[..]));
        let mut out = String::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "demo/Chart.yaml" {
                entry.read_to_string(&mut out).unwrap();
            }
        }
        out
    };
    assert!(
        layer_text.contains("oci://proxy.test/charts.bitnami.com/bitnami"),
        "dependency not rewritten: {layer_text}"
    );

    // digest-addressed manifest and HEAD
    let by_digest = format!("/v2/test/demo/manifests/{manifest_digest}");
    let (status, _, _) = common::send(&app, "GET", &by_digest, "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let (status, headers, body) =
        common::send(&app, "HEAD", "/v2/test/demo/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["Docker-Content-Digest"].to_str().unwrap(),
        manifest_digest
    );
    assert!(body.is_empty());
}

#[tokio::test]
async fn second_pull_serves_from_cache() {
    let server = MockServer::start().await;
    mount_upstream(&server, 1, 1).await; // exactly one upstream fetch each
    let app = common::app(&cfg(&server.uri()));
    for _ in 0..2 {
        let (status, _, _) =
            common::send(&app, "GET", "/v2/test/demo/manifests/1.0.0", "proxy.test").await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn ephemeral_alias_skips_persistent_storage() {
    let server = MockServer::start().await;
    mount_upstream(&server, 1, 1).await;
    let (app, state) = common::app_with_state(&cfg(&server.uri()));

    let (status, _, body) =
        common::send(&app, "GET", "/v2/eph/demo/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let manifest: OciManifest = serde_json::from_slice(&body).unwrap();

    // blobs are servable (from the ephemeral cache)...
    let layer_path = format!("/v2/eph/demo/blobs/{}", manifest.layers[0].digest);
    let (status, _, _) = common::send(&app, "GET", &layer_path, "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    // ...but nothing was written to the persistent backend
    assert!(
        state
            .storage
            .head_blob(&manifest.layers[0].digest)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unknown_version_is_manifest_unknown() {
    let server = MockServer::start().await;
    mount_upstream(&server, 1, 0).await;
    let app = common::app(&cfg(&server.uri()));
    let (status, _, body) =
        common::send(&app, "GET", "/v2/test/demo/manifests/9.9.9", "proxy.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
}

#[tokio::test]
async fn ssrf_hosts_are_rejected() {
    let app = common::app(common::MEMORY_CFG);
    for name in ["localhost/x", "10.0.0.1/x", "internal/x"] {
        let (status, _, body) = common::send(
            &app,
            "GET",
            &format!("/v2/{name}/manifests/1.0.0"),
            "proxy.test",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{name}");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["errors"][0]["code"], "NAME_UNKNOWN", "{name}");
    }
}

#[tokio::test]
async fn missing_blob_is_blob_unknown() {
    let app = common::app(common::MEMORY_CFG);
    let missing = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (status, _, body) = common::send(
        &app,
        "GET",
        &format!("/v2/a.io/c/blobs/{missing}"),
        "proxy.test",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["errors"][0]["code"], "BLOB_UNKNOWN");
}

#[tokio::test]
async fn config_and_layer_digests_are_not_manifests() {
    let server = MockServer::start().await;
    mount_upstream(&server, 1, 1).await;
    let app = common::app(&cfg(&server.uri()));

    let (status, _, body) =
        common::send(&app, "GET", "/v2/test/demo/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let manifest: OciManifest = serde_json::from_slice(&body).unwrap();

    for digest in [&manifest.config.digest, &manifest.layers[0].digest] {
        let path = format!("/v2/test/demo/manifests/{digest}");
        let (status, _, body) = common::send(&app, "GET", &path, "proxy.test").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }
}

#[tokio::test]
async fn metadata_less_local_storage_validates_digest_manifests() {
    let server = MockServer::start().await;
    mount_upstream(&server, 1, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = format!(
        concat!(
            "storage:\n  backend: local\n  local:\n    path: {path}\n",
            "max_chart_bytes: 65536\n",
            "aliases:\n  test:\n    upstream: {uri}\n    store: true\n",
        ),
        path = dir.path().display(),
        uri = server.uri(),
    );
    let (app, state) = common::app_with_state(&cfg);

    let (status, headers, body) =
        common::send(&app, "GET", "/v2/test/demo/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let manifest_digest = headers["Docker-Content-Digest"].to_str().unwrap();
    let manifest: OciManifest = serde_json::from_slice(&body).unwrap();
    let stored = state
        .storage
        .get_blob(&helmoci_core::oci::Digest::parse(manifest_digest).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(stored.meta.content_type.is_none());

    let manifest_path = format!("/v2/test/demo/manifests/{manifest_digest}");
    let (status, _, body) = common::send(&app, "GET", &manifest_path, "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<OciManifest>(&body).unwrap(),
        manifest
    );

    let config_path = format!("/v2/test/demo/manifests/{}", manifest.config.digest);
    let (status, _, body) = common::send(&app, "GET", &config_path, "proxy.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["errors"][0]["code"], "MANIFEST_UNKNOWN");
}
