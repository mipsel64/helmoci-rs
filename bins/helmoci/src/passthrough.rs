use crate::error::AppError;
use crate::state::AppState;
use helmoci_core::resolver::{OciTarget, UpstreamAuthKind, is_public_hostname};

#[derive(Debug, PartialEq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parse `Bearer realm="…",service="…",scope="…"`.
pub fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let parts = split_challenge_params(header.trim());
    let bearer_index = parts
        .iter()
        .position(|part| strip_prefix_ascii_case(part, "Bearer ").is_some())?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for (index, part) in parts.iter().enumerate().skip(bearer_index) {
        let part = if index == bearer_index {
            strip_prefix_ascii_case(part, "Bearer ")?
        } else {
            part
        };
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        let key = key.trim();
        if key.eq_ignore_ascii_case("realm") {
            realm = Some(value);
        } else if key.eq_ignore_ascii_case("service") {
            service = Some(value);
        } else if key.eq_ignore_ascii_case("scope") {
            scope = Some(value);
        }
    }
    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())?
        .eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
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

fn registry_url(target: &OciTarget) -> Result<url::Url, AppError> {
    let scheme = if target.plain_http { "http" } else { "https" };
    url::Url::parse(&format!("{scheme}://{}", target.registry))
        .map_err(|_| AppError::Upstream("invalid OCI registry authority".into()))
}

fn has_public_domain(url: &url::Url) -> bool {
    matches!(url.host(), Some(url::Host::Domain(host)) if is_public_hostname(host))
}

async fn build_token_request(
    state: &AppState,
    target: &OciTarget,
    challenge: &BearerChallenge,
) -> Result<reqwest::RequestBuilder, AppError> {
    let target_url = registry_url(target)?;
    let mut realm_url = url::Url::parse(&challenge.realm)
        .map_err(|error| AppError::Upstream(format!("invalid registry token realm: {error}")))?;
    if !matches!(realm_url.scheme(), "http" | "https") {
        return Err(AppError::Upstream(
            "registry token realm must use http or https".into(),
        ));
    }
    let same_origin = target_url.origin() == realm_url.origin();
    let client = match target.auth {
        UpstreamAuthKind::Gcp => {
            if target.plain_http {
                return Err(AppError::Upstream(
                    "gcp registry authentication requires an HTTPS target".into(),
                ));
            }
            if realm_url.scheme() != "https" {
                return Err(AppError::Upstream(
                    "gcp registry token realm must use HTTPS".into(),
                ));
            }
            if !same_origin {
                return Err(AppError::Upstream(
                    "gcp registry token realm must match the registry origin".into(),
                ));
            }
            if !has_public_domain(&target_url) || !has_public_domain(&realm_url) {
                return Err(AppError::Upstream(
                    "gcp registry token realm must use a public hostname".into(),
                ));
            }
            &state.public_http
        }
        UpstreamAuthKind::None if same_origin => &state.token_http,
        UpstreamAuthKind::None => {
            if !has_public_domain(&realm_url) {
                return Err(AppError::Upstream(
                    "cross-origin registry token realm must use a public hostname".into(),
                ));
            }
            &state.public_http
        }
    };

    let fallback_scope = format!("repository:{}:pull", target.repo);
    {
        let mut query = realm_url.query_pairs_mut();
        if let Some(service) = &challenge.service {
            query.append_pair("service", service);
        }
        query.append_pair(
            "scope",
            challenge.scope.as_deref().unwrap_or(&fallback_scope),
        );
    }

    let mut request = client.get(realm_url);
    if target.auth == UpstreamAuthKind::Gcp {
        let gcp = state.gcp.as_ref().ok_or_else(|| {
            AppError::Internal(
                "alias requires gcp auth but GCP credentials were not initialized".into(),
            )
        })?;
        request = request.basic_auth("oauth2accesstoken", Some(gcp.access_token().await?));
    }
    Ok(request)
}

pub async fn fetch_token(
    state: &AppState,
    target: &OciTarget,
    challenge: &BearerChallenge,
) -> Result<String, AppError> {
    let response = build_token_request(state, target, challenge)
        .await?
        .send()
        .await
        .map_err(|error| {
            AppError::Upstream(format!("token request failed: {}", error.without_url()))
        })?;
    if !response.status().is_success() {
        return Err(AppError::Upstream(format!(
            "token endpoint returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let body: TokenResponse = response.json().await.map_err(|error| {
        AppError::Upstream(format!("invalid token response: {}", error.without_url()))
    })?;
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
    use helmoci_core::resolver::{OciTarget, UpstreamAuthKind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct CountingGcp {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl GcpTokenProvider for CountingGcp {
        async fn access_token(&self) -> Result<String, crate::error::AppError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok("fake-gcp-token".to_string())
        }
    }

    fn state() -> SharedState {
        let rc = parse_config("storage:\n  type: memory\n").unwrap();
        let storage = build_storage(&rc.settings.storage).unwrap();
        AppState::new(rc, storage, None).unwrap()
    }

    fn counting_gcp_state() -> (SharedState, Arc<AtomicUsize>) {
        let rc = parse_config("storage:\n  type: memory\n").unwrap();
        let storage = build_storage(&rc.settings.storage).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider: Arc<dyn GcpTokenProvider> = Arc::new(CountingGcp {
            calls: calls.clone(),
        });
        (AppState::new(rc, storage, Some(provider)).unwrap(), calls)
    }

    fn target(registry: impl Into<String>, auth: UpstreamAuthKind, plain_http: bool) -> OciTarget {
        OciTarget {
            registry: registry.into(),
            repo: "x".into(),
            full_name: "alias/x".into(),
            store: false,
            auth,
            plain_http,
        }
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

    #[test]
    fn parses_mixed_case_bearer_scheme_and_parameter_names() {
        let challenge = parse_bearer_challenge(
            "bEaReR ReAlM=\"https://auth.example/token\",SeRvIcE=\"reg.example\",ScOpE=\"repository:a/b:pull\"",
        )
        .unwrap();

        assert_eq!(challenge.realm, "https://auth.example/token");
        assert_eq!(challenge.service.as_deref(), Some("reg.example"));
        assert_eq!(challenge.scope.as_deref(), Some("repository:a/b:pull"));
    }

    #[test]
    fn finds_bearer_challenge_after_another_challenge() {
        let challenge = parse_bearer_challenge(
            "Basic realm=\"legacy\", Bearer realm=\"https://auth.example/token\",service=\"reg.example\"",
        )
        .unwrap();

        assert_eq!(challenge.realm, "https://auth.example/token");
        assert_eq!(challenge.service.as_deref(), Some("reg.example"));
    }

    #[tokio::test]
    async fn rejects_plaintext_gcp_target_before_obtaining_a_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "must-not-be-returned"
            })))
            .expect(0)
            .mount(&server)
            .await;
        let (state, calls) = counting_gcp_state();
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::Gcp,
            true,
        );
        let challenge = BearerChallenge {
            realm: format!(
                "https://{}/token",
                server.uri().trim_start_matches("http://")
            ),
            service: None,
            scope: None,
        };

        let error = fetch_token(&state, &target, &challenge).await.unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.verify().await;
    }

    #[tokio::test]
    async fn rejects_plaintext_gcp_realm_before_obtaining_a_token() {
        let (state, calls) = counting_gcp_state();
        let target = target("registry.example", UpstreamAuthKind::Gcp, false);
        let challenge = BearerChallenge {
            realm: "http://registry.example/token".into(),
            service: None,
            scope: None,
        };

        let error = build_token_request(&state, &target, &challenge)
            .await
            .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejects_cross_origin_gcp_realm_before_obtaining_a_token() {
        let (state, calls) = counting_gcp_state();
        let target = target("registry.example", UpstreamAuthKind::Gcp, false);
        let challenge = BearerChallenge {
            realm: "https://auth.example/token".into(),
            service: None,
            scope: None,
        };

        let error = build_token_request(&state, &target, &challenge)
            .await
            .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejects_cross_origin_private_anonymous_realm_without_contact() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "must-not-be-returned"
            })))
            .expect(0)
            .mount(&server)
            .await;
        let target = target("registry.example", UpstreamAuthKind::None, false);
        let challenge = BearerChallenge {
            realm: format!("http://localhost:{}/token", server.address().port()),
            service: None,
            scope: None,
        };

        let error = fetch_token(&state(), &target, &challenge)
            .await
            .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
        server.verify().await;
    }

    #[tokio::test]
    async fn rejects_cross_origin_ip_literal_anonymous_realm_without_contact() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "must-not-be-returned"
            })))
            .expect(0)
            .mount(&server)
            .await;
        let target = target("registry.example", UpstreamAuthKind::None, false);
        let challenge = BearerChallenge {
            realm: format!("{}/token", server.uri()),
            service: None,
            scope: None,
        };

        let error = fetch_token(&state(), &target, &challenge)
            .await
            .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
        server.verify().await;
    }

    #[tokio::test]
    async fn preserves_same_origin_local_anonymous_token_flow() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .and(query_param("scope", "repository:x:pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "local-token"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );
        let challenge = BearerChallenge {
            realm: format!("{}/token", server.uri()),
            service: None,
            scope: None,
        };

        let token = fetch_token(&state(), &target, &challenge).await.unwrap();

        assert_eq!(token, "local-token");
        server.verify().await;
    }

    #[tokio::test]
    async fn does_not_follow_anonymous_token_redirects() {
        let redirected = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "redirected-token"
            })))
            .expect(0)
            .mount(&redirected)
            .await;
        let registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/token", redirected.uri())),
            )
            .expect(1)
            .mount(&registry)
            .await;
        let target = target(
            registry.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );
        let challenge = BearerChallenge {
            realm: format!("{}/redirect", registry.uri()),
            service: None,
            scope: None,
        };

        let error = fetch_token(&state(), &target, &challenge)
            .await
            .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
        redirected.verify().await;
        registry.verify().await;
    }

    #[tokio::test]
    async fn redacts_realm_query_secrets_from_transport_errors() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let registry = listener.local_addr().unwrap().to_string();
        drop(listener);
        let target = target(&registry, UpstreamAuthKind::None, true);
        let challenge = BearerChallenge {
            realm: format!("http://{registry}/token?client_secret=HELMOCI_REDACTION_SENTINEL"),
            service: None,
            scope: None,
        };

        let error = fetch_token(&state(), &target, &challenge)
            .await
            .unwrap_err();
        let crate::error::AppError::Upstream(message) = error else {
            panic!("transport failures should be upstream errors");
        };

        assert!(!message.contains("client_secret"), "{message}");
        assert!(!message.contains("HELMOCI_REDACTION_SENTINEL"), "{message}");
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
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let token = fetch_token(&state(), &target, &challenge).await.unwrap();

        assert_eq!(token, "anon-token");
        server.verify().await;
    }

    #[tokio::test]
    async fn builds_gcp_basic_auth_for_valid_https_same_origin_without_sending() {
        let (state, calls) = counting_gcp_state();
        let expected =
            base64::engine::general_purpose::STANDARD.encode("oauth2accesstoken:fake-gcp-token");
        let target = target("registry.example", UpstreamAuthKind::Gcp, false);
        let challenge = BearerChallenge {
            realm: "https://REGISTRY.EXAMPLE:443/token".into(),
            service: None,
            scope: None,
        };

        let request = build_token_request(&state, &target, &challenge)
            .await
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("registry.example"));
        assert_eq!(request.url().path(), "/token");
        assert_eq!(
            request.headers()[reqwest::header::AUTHORIZATION],
            format!("Basic {expected}")
        );
        assert!(
            request
                .url()
                .query_pairs()
                .any(|(key, value)| key == "scope" && value == "repository:x:pull")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn gcp_auth_requires_an_initialized_provider() {
        let target = target("registry.example", UpstreamAuthKind::Gcp, false);
        let challenge = BearerChallenge {
            realm: "https://registry.example/token".into(),
            service: None,
            scope: None,
        };

        let error = fetch_token(&state(), &target, &challenge)
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
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let error = fetch_token(&state(), &target, &challenge)
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
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let error = fetch_token(&state(), &target, &challenge)
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
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let error = fetch_token(&state(), &target, &challenge)
            .await
            .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
    }
}
