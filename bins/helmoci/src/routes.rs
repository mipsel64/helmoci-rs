use crate::classic;
use crate::error::AppError;
use crate::state::SharedState;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use helmoci_core::oci::route::{OciRoute, parse_oci_path};
use helmoci_core::resolver::{Resolved, resolve_name};

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(healthz))
        .fallback(oci_dispatch)
        .with_state(state)
}

async fn home() -> Html<&'static str> {
    Html(include_str!("home.html"))
}

async fn healthz() -> &'static str {
    "ok"
}

pub fn invalid_path_message(name: &str) -> String {
    format!(
        "Invalid OCI path {name:?}. Use a configured alias or a public host and chart name: \
         oci://<proxy>/<host>/<repo-path>/<chart> (e.g. argoproj.github.io/argo-helm/argo-cd). \
         Localhost and raw IP addresses are not allowed."
    )
}

/// Host clients should use for rewritten oci:// dependency URLs.
fn proxy_host_from(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn api_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .body(Body::empty())
        .expect("static headers are valid")
}

async fn oci_dispatch(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let path = req.uri().path().to_string();
    if path != "/v2" && !path.starts_with("/v2/") {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    let head_only = match *req.method() {
        Method::GET => false,
        Method::HEAD => true,
        _ => return AppError::Unsupported("only GET/HEAD are supported".into()).into_response(),
    };
    let proxy_host = proxy_host_from(req.headers());
    let query = req.uri().query().map(str::to_string);

    let result = match parse_oci_path(&path) {
        OciRoute::Api => Ok(api_response()),
        OciRoute::Manifest { name, reference } => {
            manifest_entry(&state, &proxy_host, &name, &reference, head_only).await
        }
        OciRoute::Blob { name, digest } => blob_entry(&state, &name, &digest, head_only).await,
        OciRoute::Tags { name } => tags_entry(&state, &name, query.as_deref(), head_only).await,
        OciRoute::NotFound => Err(AppError::NameUnknown("unknown registry path".into())),
    };
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn manifest_entry(
    state: &SharedState,
    proxy_host: &str,
    name: &str,
    reference: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    match resolve_name(name, &state.cfg.aliases) {
        Some(Resolved::Classic(chart)) => {
            classic::manifest(state, proxy_host, chart, reference, head_only).await
        }
        Some(Resolved::Oci(_)) => Err(AppError::Internal(
            "oci pass-through is wired in a later task".into(),
        )),
        None => Err(AppError::NameUnknown(invalid_path_message(name))),
    }
}

async fn blob_entry(
    state: &SharedState,
    name: &str,
    digest: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    match resolve_name(name, &state.cfg.aliases) {
        Some(Resolved::Classic(_)) => classic::blob(state, digest, head_only).await,
        Some(Resolved::Oci(_)) => Err(AppError::Internal(
            "oci pass-through is wired in a later task".into(),
        )),
        None => Err(AppError::NameUnknown(invalid_path_message(name))),
    }
}

async fn tags_entry(
    state: &SharedState,
    name: &str,
    query: Option<&str>,
    head_only: bool,
) -> Result<Response, AppError> {
    match resolve_name(name, &state.cfg.aliases) {
        Some(Resolved::Classic(chart)) => classic::tags(state, chart, query, head_only).await,
        Some(Resolved::Oci(_)) => Err(AppError::Internal(
            "oci pass-through is wired in a later task".into(),
        )),
        None => Err(AppError::NameUnknown(invalid_path_message(name))),
    }
}
