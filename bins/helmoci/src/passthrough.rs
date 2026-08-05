use crate::error::AppError;
use crate::state::AppState;
use helmoci_core::resolver::UpstreamAuthKind;

#[derive(Debug, PartialEq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parse `Bearer realm="…",service="…",scope="…"`.
pub fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let rest = header.trim().strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in split_challenge_params(rest) {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }
    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

fn split_challenge_params(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for character in value.chars() {
        match character {
            '"' => {
                in_quotes = !in_quotes;
                current.push(character);
            }
            ',' if !in_quotes => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

pub async fn fetch_token(
    state: &AppState,
    challenge: &BearerChallenge,
    auth: &UpstreamAuthKind,
    fallback_scope: &str,
) -> Result<String, AppError> {
    let mut url = url::Url::parse(&challenge.realm).map_err(|error| {
        AppError::Upstream(format!("invalid token realm {}: {error}", challenge.realm))
    })?;
    {
        let mut query = url.query_pairs_mut();
        if let Some(service) = &challenge.service {
            query.append_pair("service", service);
        }
        query.append_pair(
            "scope",
            challenge.scope.as_deref().unwrap_or(fallback_scope),
        );
    }

    let mut request = state.http.get(url);
    if *auth == UpstreamAuthKind::Gcp {
        let gcp = state.gcp.as_ref().ok_or_else(|| {
            AppError::Internal(
                "alias requires gcp auth but GCP credentials were not initialized".into(),
            )
        })?;
        request = request.basic_auth("oauth2accesstoken", Some(gcp.access_token().await?));
    }

    let response = request
        .send()
        .await
        .map_err(|error| AppError::Upstream(format!("token request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(AppError::Upstream(format!(
            "token endpoint returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let body: TokenResponse = response
        .json()
        .await
        .map_err(|error| AppError::Upstream(format!("invalid token response: {error}")))?;
    body.token
        .or(body.access_token)
        .ok_or_else(|| AppError::Upstream("token response had no token".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{build_storage, parse_config};
    use crate::gcp::GcpTokenProvider;
    use crate::state::{AppState, SharedState};
    use async_trait::async_trait;
    use base64::Engine;
    use helmoci_core::resolver::UpstreamAuthKind;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct FakeGcp;

    #[async_trait]
    impl GcpTokenProvider for FakeGcp {
        async fn access_token(&self) -> Result<String, crate::error::AppError> {
            Ok("fake-gcp-token".to_string())
        }
    }

    fn state(gcp: bool) -> SharedState {
        let rc = parse_config("storage:\n  type: memory\n").unwrap();
        let storage = build_storage(&rc.settings.storage).unwrap();
        let gcp: Option<Arc<dyn GcpTokenProvider>> =
            if gcp { Some(Arc::new(FakeGcp)) } else { None };
        AppState::new(rc, storage, gcp).unwrap()
    }

    #[test]
    fn parses_bearer_challenge_parameters() {
        let challenge = parse_bearer_challenge(
            "Bearer realm=\"https://auth.example/token\",service=\"reg.example\",scope=\"repository:a/b:pull,push\"",
        )
        .unwrap();

        assert_eq!(challenge.realm, "https://auth.example/token");
        assert_eq!(challenge.service.as_deref(), Some("reg.example"));
        assert_eq!(challenge.scope.as_deref(), Some("repository:a/b:pull,push"));
    }

    #[test]
    fn rejects_non_bearer_and_bearer_challenges_without_a_realm() {
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_none());
        assert!(parse_bearer_challenge("Bearer service=\"no-realm\"").is_none());
    }

    #[tokio::test]
    async fn fetches_anonymous_token_with_service_and_fallback_scope() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .and(query_param("service", "reg"))
            .and(query_param("scope", "repository:x:pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "anon-token"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let challenge = BearerChallenge {
            realm: format!("{}/token", server.uri()),
            service: Some("reg".into()),
            scope: None,
        };

        let token = fetch_token(
            &state(false),
            &challenge,
            &UpstreamAuthKind::None,
            "repository:x:pull",
        )
        .await
        .unwrap();

        assert_eq!(token, "anon-token");
        server.verify().await;
    }

    #[tokio::test]
    async fn gcp_auth_sends_oauth2accesstoken_basic_and_accepts_access_token() {
        let server = MockServer::start().await;
        let expected =
            base64::engine::general_purpose::STANDARD.encode("oauth2accesstoken:fake-gcp-token");
        Mock::given(method("GET"))
            .and(path("/token"))
            .and(query_param("scope", "repository:x:pull"))
            .and(header(
                "authorization",
                format!("Basic {expected}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gcp-registry-token"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let challenge = BearerChallenge {
            realm: format!("{}/token", server.uri()),
            service: None,
            scope: Some("repository:x:pull".into()),
        };

        let token = fetch_token(&state(true), &challenge, &UpstreamAuthKind::Gcp, "unused")
            .await
            .unwrap();

        assert_eq!(token, "gcp-registry-token");
        server.verify().await;
    }

    #[tokio::test]
    async fn gcp_auth_requires_an_initialized_provider() {
        let challenge = BearerChallenge {
            realm: "https://auth.example/token".into(),
            service: None,
            scope: None,
        };

        let error = fetch_token(
            &state(false),
            &challenge,
            &UpstreamAuthKind::Gcp,
            "repository:x:pull",
        )
        .await
        .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Internal(_)));
    }

    #[tokio::test]
    async fn maps_non_success_token_response_to_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let challenge = BearerChallenge {
            realm: format!("{}/token", server.uri()),
            service: None,
            scope: None,
        };

        let error = fetch_token(
            &state(false),
            &challenge,
            &UpstreamAuthKind::None,
            "repository:x:pull",
        )
        .await
        .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
    }

    #[tokio::test]
    async fn maps_invalid_token_json_to_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .mount(&server)
            .await;
        let challenge = BearerChallenge {
            realm: format!("{}/token", server.uri()),
            service: None,
            scope: None,
        };

        let error = fetch_token(
            &state(false),
            &challenge,
            &UpstreamAuthKind::None,
            "repository:x:pull",
        )
        .await
        .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
    }

    #[tokio::test]
    async fn rejects_token_response_without_a_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let challenge = BearerChallenge {
            realm: format!("{}/token", server.uri()),
            service: None,
            scope: None,
        };

        let error = fetch_token(
            &state(false),
            &challenge,
            &UpstreamAuthKind::None,
            "repository:x:pull",
        )
        .await
        .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
    }
}
