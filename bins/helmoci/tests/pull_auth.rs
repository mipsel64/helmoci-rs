mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use http_body_util::BodyExt;
use tower::util::ServiceExt;

const CFG: &str = concat!(
    "storage:\n  type: memory\n",
    "auth:\n  enabled: true\n  tokens: [\"sekrit\"]\n",
);

async fn send_authed(
    app: &axum::Router,
    path: &str,
    auth: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::get(path).header("host", "proxy.test");
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn assert_unauthorized(app: &axum::Router, auth: Option<&str>, secrets: &[&str]) {
    let response = send_authed(app, "/v2/", auth).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Basic realm=\"helmoci\""
    );
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()["Docker-Distribution-API-Version"],
        "registry/2.0"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["errors"][0]["code"], "UNAUTHORIZED");
    assert_eq!(value["errors"][0]["message"], "authentication required");
    let body = String::from_utf8(body.to_vec()).unwrap();
    for secret in secrets {
        assert!(
            !body.contains(secret),
            "response reflected secret {secret:?}"
        );
    }
}

#[tokio::test]
async fn rejects_missing_or_wrong_credentials_with_typed_challenge() {
    let app = common::app(CFG);
    assert_unauthorized(&app, None, &["sekrit"]).await;
    assert_unauthorized(&app, Some("Bearer wrong-token"), &["sekrit", "wrong-token"]).await;
}

#[tokio::test]
async fn accepts_bearer_and_basic() {
    let app = common::app(CFG);
    assert_eq!(
        send_authed(&app, "/v2/", Some("Bearer sekrit"))
            .await
            .status(),
        StatusCode::OK
    );
    let basic = base64::engine::general_purpose::STANDARD.encode("anyuser:sekrit");
    assert_eq!(
        send_authed(&app, "/v2/", Some(&format!("Basic {basic}")))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn public_paths_bypass_auth_without_changing_responses() {
    let app = common::app(CFG);
    for (path, expected) in [
        ("/", StatusCode::OK),
        ("/healthz", StatusCode::OK),
        ("/metrics", StatusCode::NOT_FOUND),
    ] {
        let response = send_authed(&app, path, None).await;
        assert_eq!(response.status(), expected, "{path}");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    }
}

#[tokio::test]
async fn disabled_auth_allows_anonymous_registry_requests() {
    let app = common::app(common::MEMORY_CFG);
    assert_eq!(
        send_authed(&app, "/v2/", None).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn authentication_schemes_are_ascii_case_insensitive() {
    let app = common::app(CFG);
    assert_eq!(
        send_authed(&app, "/v2", Some("bEaReR sekrit"))
            .await
            .status(),
        StatusCode::OK
    );
    let basic = base64::engine::general_purpose::STANDARD.encode("user:sekrit");
    assert_eq!(
        send_authed(&app, "/v2", Some(&format!("bAsIc {basic}")))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejects_malformed_or_empty_credentials() {
    let app = common::app(CFG);
    let no_colon = base64::engine::general_purpose::STANDARD.encode("sekrit");
    let empty_password = base64::engine::general_purpose::STANDARD.encode("user:");
    let non_utf8 = base64::engine::general_purpose::STANDARD.encode([0xff, b':', b'x']);
    let cases = [
        "Bearer",
        "Bearer ",
        "Bearer  sekrit",
        "Bearer sekrit ",
        "Basic",
        "Basic ",
        "Basic !!!",
        &format!("Basic {no_colon}"),
        &format!("Basic {empty_password}"),
        &format!("Basic {non_utf8}"),
        "Digest sekrit",
    ];
    for value in cases {
        assert_unauthorized(&app, Some(value), &["sekrit"]).await;
    }
}

#[tokio::test]
async fn rejects_repeated_authorization_fields() {
    let app = common::app(CFG);
    let request = Request::get("/v2/")
        .header("host", "proxy.test")
        .header(header::AUTHORIZATION, "Bearer sekrit")
        .header(header::AUTHORIZATION, "Bearer sekrit")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn public_path_matching_is_exact() {
    let app = common::app(CFG);
    for path in ["/healthz/", "/metrics/", "/healthz-extra", "/metrics-extra"] {
        let response = send_authed(&app, path, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn valid_auth_preserves_non_registry_not_found_behavior() {
    let app = common::app(CFG);
    let response = send_authed(&app, "/not-a-registry-path", Some("Bearer sekrit")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
}
