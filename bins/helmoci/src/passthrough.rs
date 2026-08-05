use crate::error::AppError;
use crate::respond::bytes_response;
use crate::state::AppState;
use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{Stream, StreamExt, TryStreamExt};
use helmoci_core::oci::{Digest, MEDIA_TYPE_MANIFEST, TagPointer};
use helmoci_core::resolver::{OciTarget, UpstreamAuthKind, is_public_hostname};
use helmoci_storage::{Blob, TagScope};

const DEFAULT_MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

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

fn upstream_url(target: &OciTarget, suffix: &str) -> Result<url::Url, AppError> {
    let scheme = if target.plain_http { "http" } else { "https" };
    let mut url = url::Url::parse(&format!("{scheme}://{}/", target.registry))
        .map_err(|_| AppError::Upstream("invalid OCI upstream target".into()))?;
    let (path, query) = suffix.split_once('?').unwrap_or((suffix, ""));
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| AppError::Upstream("invalid OCI upstream target".into()))?;
        segments.pop_if_empty();
        segments.push("v2");
        segments.extend(target.repo.split('/'));
        segments.extend(path.split('/'));
    }
    if !query.is_empty() {
        url.set_query(Some(query));
    }
    Ok(url)
}

fn upstream_token_cache_key(target: &OciTarget) -> String {
    let scheme = if target.plain_http { "http" } else { "https" };
    let auth = match target.auth {
        UpstreamAuthKind::None => "none",
        UpstreamAuthKind::Gcp => "gcp",
    };
    format!("{scheme}|{auth}|{}|{}", target.registry, target.repo)
}

fn header_str(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn is_manifest_media_type(content_type: &str) -> bool {
    matches!(
        content_type.split(';').next().map(str::trim),
        Some(
            MEDIA_TYPE_MANIFEST
                | OCI_INDEX_MEDIA_TYPE
                | DOCKER_MANIFEST_MEDIA_TYPE
                | DOCKER_MANIFEST_LIST_MEDIA_TYPE
        )
    )
}

fn manifest_media_type(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    (value.get("schemaVersion")?.as_u64() == Some(2))
        .then(|| value.get("mediaType")?.as_str())?
        .filter(|media_type| is_manifest_media_type(media_type))
        .map(str::to_string)
}

fn accepts_media_type(accept: Option<&str>, media_type: &str) -> bool {
    accept.is_none_or(|accept| {
        accept.split(',').any(|range| {
            let mut parts = range.split(';');
            let range = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let acceptable = parts.all(|parameter| {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    return true;
                };
                !name.trim().eq_ignore_ascii_case("q")
                    || value
                        .trim()
                        .parse::<f32>()
                        .is_ok_and(|quality| quality > 0.0)
            });
            acceptable
                && (range == "*/*"
                    || range == media_type
                    || range
                        .strip_suffix("/*")
                        .is_some_and(|kind| media_type.starts_with(&format!("{kind}/"))))
        })
    })
}

async fn read_bounded<T>(
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

async fn read_cached_blob(blob: Blob, max_bytes: u64) -> Result<Vec<u8>, AppError> {
    read_bounded(Some(blob.meta.size), blob.data, max_bytes, AppError::from).await
}

async fn read_upstream_body(
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

fn is_link_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn consume_link_ows(bytes: &[u8], position: &mut usize) {
    while matches!(bytes.get(*position), Some(b' ' | b'\t')) {
        *position += 1;
    }
}

fn valid_link_params(params: &str) -> bool {
    let bytes = params.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        consume_link_ows(bytes, &mut position);
        if bytes.get(position) != Some(&b';') {
            return false;
        }
        position += 1;
        consume_link_ows(bytes, &mut position);

        let name_start = position;
        while bytes.get(position).is_some_and(|byte| is_link_token(*byte)) {
            position += 1;
        }
        if position == name_start {
            return false;
        }
        consume_link_ows(bytes, &mut position);
        if bytes.get(position) != Some(&b'=') {
            continue;
        }
        position += 1;
        consume_link_ows(bytes, &mut position);

        if bytes.get(position) == Some(&b'"') {
            position += 1;
            let mut has_value = false;
            loop {
                let Some(byte) = bytes.get(position) else {
                    return false;
                };
                position += 1;
                match byte {
                    b'"' if has_value => break,
                    b'"' => return false,
                    b'\\' => {
                        let Some(escaped) = bytes.get(position) else {
                            return false;
                        };
                        if *escaped < b' ' || *escaped == 0x7f {
                            return false;
                        }
                        has_value = true;
                        position += 1;
                    }
                    byte if *byte < b' ' || *byte == 0x7f => return false,
                    _ => has_value = true,
                }
            }
        } else {
            let value_start = position;
            while bytes.get(position).is_some_and(|byte| is_link_token(*byte)) {
                position += 1;
            }
            if position == value_start {
                return false;
            }
        }
        consume_link_ows(bytes, &mut position);
    }
    true
}

fn is_safe_uri_reference(reference: &str) -> bool {
    let bytes = reference.as_bytes();
    let mut position = 0;
    while let Some(byte) = bytes.get(position) {
        if !matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
        ) {
            return false;
        }
        if *byte == b'%' {
            let Some(encoded) = bytes.get(position + 1..position + 3) else {
                return false;
            };
            if !encoded.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            position += 3;
        } else {
            position += 1;
        }
    }
    true
}

fn resolved_tag_link_url(reference: &str, target: &OciTarget) -> Option<url::Url> {
    if !is_safe_uri_reference(reference) {
        return None;
    }
    let target_url = upstream_url(target, "tags/list").ok()?;
    let resolved = url::Url::parse(reference)
        .or_else(|_| target_url.join(reference))
        .ok()?;
    (resolved.origin() == target_url.origin()
        && resolved.path() == target_url.path()
        && resolved.fragment().is_none())
    .then_some(resolved)
}

fn rewrite_tag_link(link: &str, target: &OciTarget) -> Option<String> {
    let link = link.trim_matches([' ', '\t']);
    if link
        .bytes()
        .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
    {
        return None;
    }
    let uri = link.strip_prefix('<')?.split_once('>')?;
    if !uri.1.is_empty() && !valid_link_params(uri.1) {
        return None;
    }
    let resolved = resolved_tag_link_url(uri.0, target)?;
    let query = resolved.query().unwrap_or_default();
    let suffix = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    Some(format!(
        "</v2/{}/tags/list{}>{}",
        target.full_name, suffix, uri.1
    ))
}

fn rewrite_upstream_tag_link(response: &reqwest::Response, target: &OciTarget) -> Option<String> {
    let mut values = response.headers().get_all(header::LINK).iter();
    let link = values.next()?.to_str().ok()?;
    values
        .next()
        .is_none()
        .then(|| rewrite_tag_link(link, target))?
}

async fn cached_manifest_response(
    digest: &Digest,
    blob: Blob,
    head_only: bool,
    max_bytes: u64,
) -> Result<Response, AppError> {
    let bytes = read_cached_blob(blob, max_bytes).await?;
    if Digest::sha256(&bytes) != *digest {
        return Err(AppError::ManifestUnknown(format!(
            "manifest unknown: {digest}"
        )));
    }
    let Some(media_type) = manifest_media_type(&bytes) else {
        return Err(AppError::ManifestUnknown(format!(
            "manifest unknown: {digest}"
        )));
    };
    Ok(bytes_response(&media_type, digest, bytes, head_only))
}

/// GET/HEAD an upstream /v2 path, doing the Docker token dance on 401.
pub async fn send_upstream(
    state: &AppState,
    target: &OciTarget,
    method: reqwest::Method,
    suffix: &str,
    accept: Option<&str>,
) -> Result<reqwest::Response, AppError> {
    if target.auth == UpstreamAuthKind::Gcp && target.plain_http {
        return Err(AppError::Upstream(
            "gcp registry authentication requires an HTTPS target".into(),
        ));
    }

    let url = upstream_url(target, suffix)?;
    let cache_key = upstream_token_cache_key(target);
    let build = |token: Option<String>| {
        let mut request = state.http.request(method.clone(), url.clone());
        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request
    };

    let response = build(state.upstream_tokens.get(&cache_key).await)
        .send()
        .await
        .map_err(|error| {
            AppError::Upstream(format!("upstream request failed: {}", error.without_url()))
        })?;
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(response);
    }

    let challenge = response
        .headers()
        .get_all("www-authenticate")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(parse_bearer_challenge);
    let Some(challenge) = challenge else {
        return Err(AppError::Upstream(
            "upstream returned 401 without a usable bearer challenge".into(),
        ));
    };
    let token = fetch_token(state, target, &challenge).await?;
    state.upstream_tokens.insert(cache_key, token.clone()).await;
    build(Some(token)).send().await.map_err(|error| {
        AppError::Upstream(format!("upstream request failed: {}", error.without_url()))
    })
}

pub async fn manifest(
    state: &AppState,
    proxy_host: &str,
    target: OciTarget,
    reference: &str,
    head_only: bool,
    accept: Option<String>,
) -> Result<Response, AppError> {
    let max_bytes = state.cfg.settings.max_chart_bytes;
    if target.store {
        if let Some(digest) = Digest::parse(reference) {
            if let Some(blob) = state.storage.get_blob(&digest).await? {
                return cached_manifest_response(&digest, blob, head_only, max_bytes).await;
            }
        } else {
            let scope = TagScope {
                proxy_host,
                full_name: &target.full_name,
            };
            if let Some(pointer) = state.storage.get_tag_pointer(&scope, reference).await?
                && is_manifest_media_type(&pointer.media_type)
                && accepts_media_type(accept.as_deref(), &pointer.media_type)
                && let Some(blob) = state.storage.get_blob(&pointer.digest).await?
            {
                return cached_manifest_response(&pointer.digest, blob, head_only, max_bytes).await;
            }
        }
    }

    let method = if head_only {
        reqwest::Method::HEAD
    } else {
        reqwest::Method::GET
    };
    let accept = accept.as_deref().unwrap_or(DEFAULT_MANIFEST_ACCEPT);
    let response = send_upstream(
        state,
        &target,
        method,
        &format!("manifests/{reference}"),
        Some(accept),
    )
    .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(AppError::ManifestUnknown(format!(
            "upstream manifest unknown: {}:{reference}",
            target.full_name
        )));
    }
    if !response.status().is_success() {
        return Err(AppError::Upstream(format!(
            "upstream registry returned HTTP {} for manifests/{reference}",
            response.status().as_u16()
        )));
    }
    let content_type =
        header_str(&response, "content-type").unwrap_or_else(|| MEDIA_TYPE_MANIFEST.to_string());

    if head_only {
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, &content_type)
            .header("Docker-Distribution-API-Version", "registry/2.0");
        if let Some(length) = response.content_length() {
            builder = builder.header(header::CONTENT_LENGTH, length);
        }
        if let Some(digest) = header_str(&response, "docker-content-digest") {
            builder = builder.header("Docker-Content-Digest", digest);
        }
        if let Some(etag) = header_str(&response, "etag") {
            builder = builder.header(header::ETAG, etag);
        }
        return Ok(builder
            .body(Body::empty())
            .expect("static headers are valid"));
    }

    let bytes = read_upstream_body(response, max_bytes, "manifest").await?;
    let digest = Digest::sha256(&bytes);
    if let Some(requested_digest) = Digest::parse(reference)
        && requested_digest != digest
    {
        return Err(AppError::Upstream(format!(
            "upstream manifest bytes did not match requested digest {requested_digest}"
        )));
    }
    let Some(media_type) = manifest_media_type(&bytes) else {
        return Err(AppError::Upstream(
            "upstream response was not a supported OCI manifest".into(),
        ));
    };
    if target.store {
        state
            .storage
            .put_blob(&digest, &media_type, bytes.clone().into())
            .await?;
        if Digest::parse(reference).is_none() {
            let scope = TagScope {
                proxy_host,
                full_name: &target.full_name,
            };
            let pointer = TagPointer {
                digest: digest.clone(),
                media_type: media_type.clone(),
                size: bytes.len() as u64,
            };
            state
                .storage
                .put_tag_pointer(&scope, reference, &pointer)
                .await?;
        }
    }
    Ok(bytes_response(&media_type, &digest, bytes.to_vec(), false))
}

pub async fn blob(
    state: &AppState,
    target: OciTarget,
    digest_str: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    let Some(digest) = Digest::parse(digest_str) else {
        return Err(AppError::BlobUnknown(format!(
            "invalid digest: {digest_str}"
        )));
    };
    if target.store
        && let Some(blob) = state.storage.get_blob(&digest).await?
    {
        let content_type = blob
            .meta
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        if let Ok(bytes) = read_cached_blob(blob, state.cfg.settings.max_chart_bytes).await
            && Digest::sha256(&bytes) == digest
        {
            return Ok(bytes_response(&content_type, &digest, bytes, head_only));
        }
    }

    let method = if head_only {
        reqwest::Method::HEAD
    } else {
        reqwest::Method::GET
    };
    let response = send_upstream(state, &target, method, &format!("blobs/{digest}"), None).await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(AppError::BlobUnknown(format!("blob unknown: {digest}")));
    }
    if !response.status().is_success() {
        return Err(AppError::Upstream(format!(
            "upstream registry returned HTTP {} for blobs/{digest}",
            response.status().as_u16()
        )));
    }
    let content_type = header_str(&response, "content-type")
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let etag = header_str(&response, "etag");
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &content_type)
        .header("Docker-Content-Digest", digest.as_str())
        .header("Docker-Distribution-API-Version", "registry/2.0");
    if head_only {
        if let Some(length) = response.content_length() {
            builder = builder.header(header::CONTENT_LENGTH, length);
        }
        if let Some(etag) = etag {
            builder = builder.header(header::ETAG, etag);
        }
        return Ok(builder
            .body(Body::empty())
            .expect("static headers are valid"));
    }

    let cacheable = target.store
        && response
            .content_length()
            .map(|length| length <= state.cfg.settings.max_chart_bytes)
            .unwrap_or(false);
    if cacheable {
        let bytes =
            read_upstream_body(response, state.cfg.settings.max_chart_bytes, "blob").await?;
        if Digest::sha256(&bytes) != digest {
            return Err(AppError::Upstream(format!(
                "upstream blob bytes did not match requested digest {digest}"
            )));
        }
        state
            .storage
            .put_blob(&digest, &content_type, bytes.clone().into())
            .await?;
        return Ok(bytes_response(
            &content_type,
            &digest,
            bytes.to_vec(),
            false,
        ));
    }
    if let Some(length) = response.content_length() {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    if let Some(etag) = etag {
        builder = builder.header(header::ETAG, etag);
    }
    let data: BoxStream<'static, Result<Bytes, std::io::Error>> =
        Box::pin(response.bytes_stream().map_err(std::io::Error::other));
    Ok(builder
        .body(Body::from_stream(data))
        .expect("static headers are valid"))
}

pub async fn tags(
    state: &AppState,
    target: OciTarget,
    query: Option<&str>,
    head_only: bool,
) -> Result<Response, AppError> {
    let suffix = match query {
        Some(query) => format!("tags/list?{query}"),
        None => "tags/list".to_string(),
    };
    let response = send_upstream(state, &target, reqwest::Method::GET, &suffix, None).await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(AppError::NameUnknown(format!(
            "upstream repository unknown: {}",
            target.full_name
        )));
    }
    if !response.status().is_success() {
        return Err(AppError::Upstream(format!(
            "upstream registry returned HTTP {} for {suffix}",
            response.status().as_u16()
        )));
    }
    let link = rewrite_upstream_tag_link(&response, &target);
    let bytes =
        read_upstream_body(response, state.cfg.settings.max_chart_bytes, "tag list").await?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Upstream("upstream tag list was not valid JSON".into()))?;
    if !value.is_object() {
        return Err(AppError::Upstream(
            "upstream tag list was not a JSON object".into(),
        ));
    }
    value["name"] = serde_json::Value::String(target.full_name);
    let body = serde_json::to_vec(&value)
        .map_err(|_| AppError::Internal("encoding rewritten tag list failed".into()))?;
    let etag = Digest::sha256(&body);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::ETAG, format!("\"{etag}\""))
        .header("Docker-Distribution-API-Version", "registry/2.0");
    if let Some(link) = link {
        builder = builder.header(header::LINK, link);
    }
    let body = if head_only {
        Body::empty()
    } else {
        Body::from(body)
    };
    Ok(builder.body(body).expect("static headers are valid"))
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
    fn accept_ranges_match_exact_type_wildcard_and_any() {
        let media_type = "application/vnd.oci.image.index.v1+json";
        assert!(accepts_media_type(Some(media_type), media_type));
        assert!(accepts_media_type(Some("application/*"), media_type));
        assert!(accepts_media_type(Some("APPLICATION/*"), media_type));
        assert!(accepts_media_type(Some("*/*"), media_type));
        assert!(accepts_media_type(
            Some("application/json, application/vnd.oci.image.index.v1+json;q=0.8"),
            media_type
        ));
        assert!(!accepts_media_type(
            Some("application/vnd.oci.image.manifest.v1+json"),
            media_type
        ));
        assert!(!accepts_media_type(Some("*/*;q=0"), media_type));
    }

    #[test]
    fn tag_links_require_the_target_origin_and_a_single_entry() {
        let target = target("registry.example", UpstreamAuthKind::None, false);
        let valid_path = "/v2/x/tags/list?n=one,two";
        assert_eq!(
            rewrite_tag_link(
                &format!("<https://registry.example{valid_path}>; rel=next"),
                &target
            ),
            Some("</v2/alias/x/tags/list?n=one,two>; rel=next".into())
        );
        assert_eq!(
            rewrite_tag_link(&format!("<{valid_path}>; rel=next"), &target),
            Some("</v2/alias/x/tags/list?n=one,two>; rel=next".into())
        );
        assert_eq!(
            rewrite_tag_link(
                &format!("<{valid_path}>; rel=next; title=\"next, \\\"page\\\"\""),
                &target
            ),
            Some(
                "</v2/alias/x/tags/list?n=one,two>; rel=next; title=\"next, \\\"page\\\"\"".into()
            )
        );
        assert_eq!(
            rewrite_tag_link(&format!("<{valid_path}>; rel=next; extension"), &target),
            Some("</v2/alias/x/tags/list?n=one,two>; rel=next; extension".into())
        );
        assert_eq!(
            rewrite_tag_link(
                "</v2/x/tags/list?n=one%20two,three%2Cfour>; rel=next",
                &target
            ),
            Some("</v2/alias/x/tags/list?n=one%20two,three%2Cfour>; rel=next".into())
        );
        for link in [
            "<http://registry.example/v2/x/tags/list?n=1>; rel=next",
            "<https://registry.example:444/v2/x/tags/list?n=1>; rel=next",
            "<https://foreign.example/v2/x/tags/list?n=1>; rel=next",
            "<https://registry.example/v2/x/tags/list?n=1>; rel=next, <https://foreign.example/v2/x/tags/list?n=2>; rel=prev",
        ] {
            assert_eq!(rewrite_tag_link(link, &target), None, "{link}");
        }
    }

    #[test]
    fn tag_links_reject_malformed_parameter_suffixes() {
        let target = target("registry.example", UpstreamAuthKind::None, false);
        let path = "/v2/x/tags/list?n=one,two";
        for link in [
            format!("<{path}>;"),
            format!("<{path}>; =next"),
            format!("<{path}>; rel="),
            format!("<{path}>; rel=\"\""),
            format!("<{path}>; title=\"unterminated"),
            format!("<{path}>; rel=next, bogus"),
            format!("<{path}>; rel=next, <{path}>; rel=prev"),
            format!("<{path}>; title=\"has\u{7}control\""),
        ] {
            assert_eq!(rewrite_tag_link(&link, &target), None, "{link}");
        }
    }

    #[test]
    fn tag_links_reject_unsafe_uri_references() {
        let target = target("registry.example", UpstreamAuthKind::None, false);
        let path = "/v2/x/tags/list";
        for link in [
            format!("<{path}?n=raw space>; rel=next"),
            format!("<{path}?n=<foreign>; rel=next"),
            format!("<{path}?n=raw>angle>; rel=next"),
            format!("<{path}?n=back\\slash>; rel=next"),
            format!("<{path}?n=control\u{7}>; rel=next"),
            format!("<{path}?n=bad%ZZ>; rel=next"),
            format!("<{path}?n=incomplete%2>; rel=next"),
            format!("<{path}?n=one#fragment>; rel=next"),
            format!("<https://registry.example{path}?n=one#fragment>; rel=next"),
        ] {
            assert_eq!(rewrite_tag_link(&link, &target), None, "{link}");
        }
    }

    #[tokio::test]
    async fn rejects_plaintext_gcp_before_cached_token_reuse() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let (state, calls) = counting_gcp_state();
        let server_uri = server.uri();
        let registry = server_uri.trim_start_matches("http://");
        let https_target = target(registry, UpstreamAuthKind::Gcp, false);
        let anonymous_target = target(registry, UpstreamAuthKind::None, false);
        let plaintext_target = target(registry, UpstreamAuthKind::Gcp, true);

        assert_ne!(
            upstream_token_cache_key(&https_target),
            upstream_token_cache_key(&plaintext_target)
        );
        assert_ne!(
            upstream_token_cache_key(&https_target),
            upstream_token_cache_key(&anonymous_target)
        );
        state
            .upstream_tokens
            .insert(
                upstream_token_cache_key(&https_target),
                "must-not-be-sent".to_string(),
            )
            .await;

        let error = send_upstream(
            &state,
            &plaintext_target,
            reqwest::Method::GET,
            "manifests/latest",
            None,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, crate::error::AppError::Upstream(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.verify().await;
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
