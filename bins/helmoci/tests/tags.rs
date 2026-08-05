mod common;

use axum::http::StatusCode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg(server_uri: &str) -> String {
    format!(
        "storage:\n  backend: memory\naliases:\n  test:\n    upstream: {server_uri}\n    store: true\n"
    )
}

async fn mount_index(server: &MockServer) {
    let index = concat!(
        "entries:\n  demo:\n",
        "    - {name: demo, version: 2.0.0, urls: [x.tgz]}\n",
        "    - {name: demo, version: 1.1.0, urls: [y.tgz]}\n",
        "    - {name: demo, version: 1.0.0, urls: [z.tgz]}\n",
    );
    Mock::given(method("GET"))
        .and(path("/index.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .mount(server)
        .await;
}

#[tokio::test]
async fn lists_all_versions() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let app = common::app(&cfg(&server.uri()));
    let (status, headers, body) =
        common::send(&app, "GET", "/v2/test/demo/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["Content-Type"], "application/json");
    assert_eq!(headers["Docker-Distribution-API-Version"], "registry/2.0");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["name"], "test/demo");
    assert_eq!(v["tags"], serde_json::json!(["2.0.0", "1.1.0", "1.0.0"]));
}

#[tokio::test]
async fn paginates_with_n_and_last() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let app = common::app(&cfg(&server.uri()));

    let (status, headers, body) =
        common::send(&app, "GET", "/v2/test/demo/tags/list?n=1", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tags"], serde_json::json!(["2.0.0"]));
    let link = headers["Link"].to_str().unwrap();
    assert!(
        link.contains("n=1") && link.contains("last=2.0.0"),
        "{link}"
    );

    let (_, _, body) = common::send(
        &app,
        "GET",
        "/v2/test/demo/tags/list?last=2.0.0",
        "proxy.test",
    )
    .await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tags"], serde_json::json!(["1.1.0", "1.0.0"]));
}

#[tokio::test]
async fn unknown_chart_is_name_unknown() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let app = common::app(&cfg(&server.uri()));
    let (status, _, body) =
        common::send(&app, "GET", "/v2/test/nope/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["errors"][0]["code"], "NAME_UNKNOWN");
    assert!(v["errors"][0]["message"].as_str().unwrap().contains("demo"));
}

#[tokio::test]
async fn percent_encodes_last_in_next_link() {
    let server = MockServer::start().await;
    let index = concat!(
        "entries:\n  demo:\n",
        "    - {name: demo, version: 2.0.0, urls: [x.tgz]}\n",
        "    - {name: demo, version: 1.1.0+build, urls: [y.tgz]}\n",
        "    - {name: demo, version: 1.0.0, urls: [z.tgz]}\n",
    );
    Mock::given(method("GET"))
        .and(path("/index.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .mount(&server)
        .await;
    let app = common::app(&cfg(&server.uri()));

    let (status, headers, body) =
        common::send(&app, "GET", "/v2/test/demo/tags/list?n=2", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tags"], serde_json::json!(["2.0.0", "1.1.0+build"]));
    assert!(
        headers["Link"]
            .to_str()
            .unwrap()
            .contains("last=1.1.0%2Bbuild")
    );
}

#[tokio::test]
async fn head_keeps_tag_metadata_and_omits_body() {
    let server = MockServer::start().await;
    mount_index(&server).await;
    let app = common::app(&cfg(&server.uri()));

    let (_, get_headers, get_body) =
        common::send(&app, "GET", "/v2/test/demo/tags/list?n=1", "proxy.test").await;
    let (status, headers, body) =
        common::send(&app, "HEAD", "/v2/test/demo/tags/list?n=1", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["Content-Type"], "application/json");
    assert_eq!(headers["Content-Length"], get_headers["Content-Length"]);
    assert_eq!(headers["Link"], get_headers["Link"]);
    assert_eq!(headers["Docker-Distribution-API-Version"], "registry/2.0");
    assert_eq!(headers["Content-Length"], get_body.len().to_string());
    assert!(body.is_empty());
}
