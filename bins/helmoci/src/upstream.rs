use crate::error::AppError;
use crate::state::AppState;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use helmoci_core::resolver::is_public_hostname;
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, LOCATION, PROXY_AUTHORIZATION};

const MAX_REDIRECTS: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitialClient {
    Trusted,
    TokenTrusted,
    Public,
}

pub(crate) fn validate_public_https(url: &url::Url) -> Result<(), AppError> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.host(), Some(url::Host::Domain(host)) if is_public_hostname(host))
    {
        return Err(AppError::Upstream(
            "cross-origin upstream must be public HTTPS without userinfo".into(),
        ));
    }
    Ok(())
}

fn redirect_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn redirect_target(
    current: &url::Url,
    response_headers: &HeaderMap,
    request_headers: &mut HeaderMap,
    client: &mut InitialClient,
) -> Result<url::Url, AppError> {
    let mut locations = response_headers.get_all(LOCATION).iter();
    let location = locations
        .next()
        .ok_or_else(|| AppError::Upstream("upstream redirect had no Location header".into()))?;
    if locations.next().is_some() {
        return Err(AppError::Upstream(
            "upstream redirect had repeated Location headers".into(),
        ));
    }
    let location = location
        .to_str()
        .map_err(|_| AppError::Upstream("upstream redirect Location was malformed".into()))?;
    let target = current
        .join(location)
        .map_err(|_| AppError::Upstream("upstream redirect Location was malformed".into()))?;
    if !matches!(target.scheme(), "http" | "https") {
        return Err(AppError::Upstream(
            "upstream redirect used an unsupported scheme".into(),
        ));
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err(AppError::Upstream(
            "upstream redirect contained userinfo".into(),
        ));
    }
    if current.scheme() == "https" && target.scheme() != "https" {
        return Err(AppError::Upstream(
            "upstream redirect attempted an HTTPS downgrade".into(),
        ));
    }
    if current.origin() != target.origin() {
        validate_public_https(&target)?;
        request_headers.remove(AUTHORIZATION);
        request_headers.remove(PROXY_AUTHORIZATION);
        request_headers.remove(COOKIE);
        *client = InitialClient::Public;
    }
    Ok(target)
}

pub(crate) async fn send(
    state: &AppState,
    method: reqwest::Method,
    mut url: url::Url,
    mut headers: HeaderMap,
    mut client: InitialClient,
    follow_redirects: bool,
) -> Result<reqwest::Response, AppError> {
    if client == InitialClient::Public {
        validate_public_https(&url)?;
    }
    let mut followed = 0;
    loop {
        let http = match client {
            InitialClient::Trusted => &state.http,
            InitialClient::TokenTrusted => &state.token_http,
            InitialClient::Public => &state.public_http,
        };
        let response = http
            .request(method.clone(), url.clone())
            .headers(headers.clone())
            .send()
            .await
            .map_err(|error| {
                AppError::Upstream(format!("upstream request failed: {}", error.without_url()))
            })?;
        if !follow_redirects || !redirect_status(response.status()) {
            return Ok(response);
        }
        if followed == MAX_REDIRECTS {
            return Err(AppError::Upstream(
                "upstream redirect limit exceeded".into(),
            ));
        }
        url = redirect_target(&url, response.headers(), &mut headers, &mut client)?;
        followed += 1;
    }
}

pub(crate) async fn read_bounded<T>(
    advertised_size: Option<u64>,
    mut data: impl Stream<Item = Result<Bytes, T>> + Unpin,
    max_bytes: u64,
    map_error: impl Fn(T) -> AppError,
) -> Result<Vec<u8>, AppError> {
    if advertised_size.is_some_and(|size| size > max_bytes) {
        return Err(AppError::TooLarge(format!(
            "upstream response exceeds size limit ({max_bytes} bytes)"
        )));
    }
    let capacity = advertised_size
        .unwrap_or_default()
        .min(max_bytes)
        .min(64 * 1024)
        .try_into()
        .unwrap_or_default();
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = data.next().await {
        let chunk = chunk.map_err(&map_error)?;
        let accumulated = u64::try_from(bytes.len())
            .ok()
            .and_then(|size| size.checked_add(u64::try_from(chunk.len()).ok()?))
            .ok_or_else(|| {
                AppError::TooLarge(format!("response exceeds size limit ({max_bytes} bytes)"))
            })?;
        if accumulated > max_bytes {
            return Err(AppError::TooLarge(format!(
                "response exceeds size limit ({max_bytes} bytes)"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) async fn read_response(
    response: reqwest::Response,
    max_bytes: u64,
    resource: &str,
) -> Result<Vec<u8>, AppError> {
    read_bounded(
        response.content_length(),
        response.bytes_stream(),
        max_bytes,
        |error| {
            AppError::Upstream(format!(
                "reading upstream {resource} failed: {}",
                error.without_url()
            ))
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{ACCEPT, HeaderValue};

    fn location(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn public_cross_origin_redirect_strips_credentials_and_retains_query() {
        let current = url::Url::parse("https://registry.example/v2/chart").unwrap();
        let mut request_headers = HeaderMap::new();
        request_headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        request_headers.insert(COOKIE, HeaderValue::from_static("session=secret"));
        request_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let mut client = InitialClient::Trusted;

        let target = redirect_target(
            &current,
            &location("https://cdn.example/chart?sig=SIGNED_QUERY_SENTINEL"),
            &mut request_headers,
            &mut client,
        )
        .unwrap();

        assert_eq!(target.query(), Some("sig=SIGNED_QUERY_SENTINEL"));
        assert_eq!(client, InitialClient::Public);
        assert!(!request_headers.contains_key(AUTHORIZATION));
        assert!(!request_headers.contains_key(COOKIE));
        assert_eq!(request_headers[ACCEPT], "application/json");
    }

    #[test]
    fn redirect_rejects_downgrade_userinfo_and_unsupported_scheme() {
        let current = url::Url::parse("https://registry.example/v2/chart").unwrap();
        for target in [
            "http://cdn.example/chart",
            "https://user:password@cdn.example/chart",
            "file:///private/chart",
        ] {
            let mut headers = HeaderMap::new();
            let mut client = InitialClient::Trusted;
            assert!(
                redirect_target(&current, &location(target), &mut headers, &mut client).is_err(),
                "{target}"
            );
        }
    }

    #[test]
    fn redirect_requires_exactly_one_well_formed_location() {
        let current = url::Url::parse("https://registry.example/v2/chart").unwrap();
        let mut repeated = HeaderMap::new();
        repeated.append(LOCATION, HeaderValue::from_static("/one"));
        repeated.append(LOCATION, HeaderValue::from_static("/two"));
        let malformed = {
            let mut headers = HeaderMap::new();
            headers.insert(LOCATION, HeaderValue::from_bytes(b"\xff").unwrap());
            headers
        };
        for response_headers in [HeaderMap::new(), repeated, malformed] {
            let mut headers = HeaderMap::new();
            let mut client = InitialClient::Trusted;
            assert!(
                redirect_target(&current, &response_headers, &mut headers, &mut client).is_err()
            );
        }
    }
}
