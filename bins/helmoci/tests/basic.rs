mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::util::ServiceExt;

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
async fn non_get_on_public_paths_returns_the_oci_error_body() {
    let app = common::app(common::MEMORY_CFG);
    for path in ["/", "/healthz", "/metrics"] {
        let (status, headers, body) = common::send(&app, "POST", path, "proxy.test").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
        assert_eq!(
            headers["Docker-Distribution-API-Version"], "registry/2.0",
            "{path}"
        );
        assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{path}");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["errors"][0]["code"], "UNSUPPORTED", "{path}");
    }
}

#[tokio::test]
async fn malformed_host_header_is_rejected_with_an_oci_error() {
    let app = common::app(common::MEMORY_CFG);
    for host in [
        "..",
        ".",
        "has space.example",
        "under_score.example",
        "-bad.example",
        "proxy.test/../evil",
        "proxy.test:0",
        "proxy.test:notaport",
    ] {
        let (status, headers, body) =
            common::send(&app, "GET", "/v2/argo/argo-cd/manifests/7.7.0", host).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{host}");
        assert_eq!(
            headers["Docker-Distribution-API-Version"], "registry/2.0",
            "{host}"
        );
        assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{host}");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["errors"][0]["code"], "NAME_INVALID", "{host}");
    }
}

#[tokio::test]
async fn local_and_literal_ip_hosts_stay_usable() {
    let app = common::app(common::MEMORY_CFG);
    for host in [
        "127.0.0.1:8080",
        "127.0.0.1",
        "localhost",
        "localhost:8080",
        "[::1]:8080",
        "charts.example.com:8443",
    ] {
        let (status, _, _) = common::send(&app, "GET", "/v2/", host).await;
        assert_eq!(status, StatusCode::OK, "{host}");
    }
}

#[tokio::test]
async fn http2_style_request_without_a_host_header_is_accepted() {
    let app = common::app(common::MEMORY_CFG);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("http://h2.example:9443/v2/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn request_without_any_host_information_is_rejected() {
    let app = common::app(common::MEMORY_CFG);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/argo/argo-cd/manifests/7.7.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["errors"][0]["code"], "NAME_INVALID");
}

#[tokio::test]
async fn v2_lookalike_non_get_is_plain_404() {
    let app = common::app(common::MEMORY_CFG);
    let (status, headers, body) = common::send(&app, "POST", "/v20", "proxy.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!headers.contains_key("Docker-Distribution-API-Version"));
    assert_eq!(&body[..], b"Not Found");
}
