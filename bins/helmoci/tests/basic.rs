mod common;

use axum::http::StatusCode;

#[tokio::test]
async fn api_version_check() {
    let app = common::app(common::MEMORY_CFG);
    let (status, headers, _) = common::send(&app, "GET", "/v2/", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["Docker-Distribution-API-Version"], "registry/2.0");
}

#[tokio::test]
async fn home_and_healthz() {
    let app = common::app(common::MEMORY_CFG);
    let (status, _, body) = common::send(&app, "GET", "/", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("helmoci"));
    let (status, _, _) = common::send(&app, "GET", "/healthz", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn non_get_head_is_405() {
    let app = common::app(common::MEMORY_CFG);
    let (status, _, body) =
        common::send(&app, "POST", "/v2/x.io/c/manifests/1", "proxy.test").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["errors"][0]["code"], "UNSUPPORTED");
}

#[tokio::test]
async fn non_v2_path_is_plain_404() {
    let app = common::app(common::MEMORY_CFG);
    let (status, _, _) = common::send(&app, "GET", "/nope", "proxy.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn v2_lookalike_get_is_plain_404() {
    let app = common::app(common::MEMORY_CFG);
    let (status, headers, body) =
        common::send(&app, "GET", "/v2evil/repo/manifests/tag", "proxy.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!headers.contains_key("Docker-Distribution-API-Version"));
    assert_eq!(&body[..], b"Not Found");
}

#[tokio::test]
async fn v2_lookalike_non_get_is_plain_404() {
    let app = common::app(common::MEMORY_CFG);
    let (status, headers, body) = common::send(&app, "POST", "/v20", "proxy.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!headers.contains_key("Docker-Distribution-API-Version"));
    assert_eq!(&body[..], b"Not Found");
}
