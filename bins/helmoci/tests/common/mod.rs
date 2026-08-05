// Each integration target uses a different subset of these shared helpers.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use bytes::Bytes;
use helmoci::config::{build_storage, parse_config};
use helmoci::gcp::GcpTokenProvider;
use helmoci::routes::build_router;
use helmoci::state::{AppState, SharedState};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::util::ServiceExt;

pub const MEMORY_CFG: &str = "storage:\n  type: memory\n";

pub fn test_state(cfg_yaml: &str) -> SharedState {
    let rc = parse_config(cfg_yaml).expect("test config parses");
    let storage = build_storage(&rc.settings.storage).expect("storage builds");
    AppState::new(rc, storage, None).expect("state builds")
}

pub fn app(cfg_yaml: &str) -> Router {
    build_router(test_state(cfg_yaml))
}

pub fn app_with_gcp(cfg_yaml: &str, gcp: Arc<dyn GcpTokenProvider>) -> Router {
    let rc = parse_config(cfg_yaml).expect("test config parses");
    let storage = build_storage(&rc.settings.storage).expect("storage builds");
    build_router(AppState::new(rc, storage, Some(gcp)).expect("state builds"))
}

pub fn app_with_state(cfg_yaml: &str) -> (Router, SharedState) {
    let state = test_state(cfg_yaml);
    (build_router(state.clone()), state)
}

pub async fn send(
    app: &Router,
    method: &str,
    path: &str,
    host: &str,
) -> (StatusCode, HeaderMap, Bytes) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}
