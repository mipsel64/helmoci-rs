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
