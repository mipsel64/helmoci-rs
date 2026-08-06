use crate::error::AppError;
use crate::state::SharedState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use constant_time_eq::constant_time_eq;

const PUBLIC_PATHS: &[&str] = &["/", "/healthz", "/metrics"];

pub async fn require_pull_auth(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if !state.cfg.settings.auth.enabled || PUBLIC_PATHS.contains(&req.uri().path()) {
        return next.run(req).await;
    }

    let mut authorization = req.headers().get_all(header::AUTHORIZATION).iter();
    let presented = authorization
        .next()
        .filter(|_| authorization.next().is_none())
        .and_then(|value| value.to_str().ok())
        .and_then(extract_token);
    let authorized = presented.is_some_and(|token| {
        state
            .cfg
            .settings
            .auth
            .tokens
            .iter()
            .filter(|expected| !expected.is_empty())
            .any(|expected| constant_time_eq(expected.as_bytes(), token.as_bytes()))
    });
    if authorized {
        return next.run(req).await;
    }

    unauthorized()
}

fn extract_token(header_value: &str) -> Option<String> {
    let (scheme, credentials) = header_value.split_once(' ')?;
    if credentials.is_empty() || credentials.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    if scheme.eq_ignore_ascii_case("Bearer") {
        return Some(credentials.to_string());
    }
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(credentials)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    (!password.is_empty()).then(|| password.to_string())
}

fn unauthorized() -> Response {
    let mut response = AppError::Unauthorized.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"helmoci\""),
    );
    response
}
