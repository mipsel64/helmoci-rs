use crate::error::AppError;
use crate::metrics::{ProxyKind, ProxySource, ProxyUpstream, UpstreamKind};
use crate::respond::{blob_bytes_response, blob_response, bytes_response};
use crate::state::{AppState, CachedToken};
use crate::upstream::{self, InitialClient};
use axum::body::Body;
use axum::http::response::Builder;
use axum::http::{StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use helmoci_core::oci::{Digest, MEDIA_TYPE_MANIFEST, TagPointer};
use helmoci_core::resolver::{OciTarget, UpstreamAuthKind, is_public_hostname};
use helmoci_storage::{Blob, StorageError, StorageOp, TagScope};
use sha2::{Digest as _, Sha256};

const DEFAULT_MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
const MANIFEST_MEDIA_TYPES: [&str; 4] = [
    MEDIA_TYPE_MANIFEST,
    OCI_INDEX_MEDIA_TYPE,
    DOCKER_MANIFEST_MEDIA_TYPE,
    DOCKER_MANIFEST_LIST_MEDIA_TYPE,
];
const OCTET_STREAM_MEDIA_TYPE: &str = "application/octet-stream";

/// Manifests and tag lists are buffered (to digest and to rewrite them) so they
/// need a bound, but they are unrelated to charts: `max_chart_bytes` is a chart
/// cap an operator may legitimately tighten to a few hundred KiB. The OCI spec
/// bounds manifests to 4 MiB, and paginated tag lists are comparable.
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TAG_LIST_BYTES: u64 = 4 * 1024 * 1024;
/// Every cached blob is verified against the requested digest; this is only the
/// bound on doing it *before* answering. Up to this size an entry is buffered, so
/// a corrupt one can still fall back to the upstream; above it the entry is hashed
/// while it streams, which cannot fall back because the response has already
/// started, but also never holds the whole blob in memory.
const MAX_BUFFERED_CACHED_BLOB_BYTES: u64 = 1024 * 1024;

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
    /// Kept untyped on purpose: registries have been seen sending this as a
    /// string or a float, and a lifetime we cannot read must fall back to the
    /// default rather than fail the whole token response.
    #[serde(default)]
    expires_in: Option<serde_json::Value>,
}

/// The advertised token lifetime in whole seconds, or `None` when the field is
/// absent, negative, not finite, or not a number we can read.
fn advertised_token_lifetime(expires_in: Option<&serde_json::Value>) -> Option<u64> {
    let seconds = match expires_in? {
        serde_json::Value::Number(number) => number.as_f64()?,
        serde_json::Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    // Saturating float-to-int casts keep an absurd advertised value finite; the
    // TTL ceiling then bounds it.
    (seconds.is_finite() && seconds >= 0.0).then_some(seconds as u64)
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
) -> Result<(reqwest::Request, InitialClient), AppError> {
    let target_url = registry_url(target)?;
    let mut realm_url = url::Url::parse(&challenge.realm)
        .map_err(|_| AppError::Upstream("invalid registry token realm".into()))?;
    if !matches!(realm_url.scheme(), "http" | "https")
        || !realm_url.username().is_empty()
        || realm_url.password().is_some()
    {
        return Err(AppError::Upstream(
            "registry token realm must use http or https without userinfo".into(),
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
            InitialClient::Public
        }
        UpstreamAuthKind::None if same_origin => InitialClient::TokenTrusted,
        UpstreamAuthKind::None => {
            upstream::validate_public_https(&realm_url)?;
            InitialClient::Public
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

    let mut request = state.http.get(realm_url);
    if target.auth == UpstreamAuthKind::Gcp {
        let gcp = state.gcp.as_ref().ok_or_else(|| {
            AppError::Internal(
                "alias requires gcp auth but GCP credentials were not initialized".into(),
            )
        })?;
        request = request.basic_auth("oauth2accesstoken", Some(gcp.access_token().await?));
    }
    let request = request.build().map_err(|error| {
        AppError::Upstream(format!("invalid token request: {}", error.without_url()))
    })?;
    Ok((request, client))
}

pub async fn fetch_token(
    state: &AppState,
    target: &OciTarget,
    challenge: &BearerChallenge,
) -> Result<CachedToken, AppError> {
    tracing::debug!("registry token refresh start");
    let result = async {
        let (request, client) = build_token_request(state, target, challenge).await?;
        let response = upstream::send(
            state,
            request.method().clone(),
            request.url().clone(),
            request.headers().clone(),
            client,
            true,
            UpstreamKind::OciToken,
        )
        .await?;
        if !response.status().is_success() {
            return Err(AppError::Upstream(format!(
                "token endpoint returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let bytes = upstream::read_response(response, 1024 * 1024, "token response").await?;
        let body: TokenResponse = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::Upstream("invalid token response".into()))?;
        let lifetime = advertised_token_lifetime(body.expires_in.as_ref());
        let token = body
            .token
            .or(body.access_token)
            .ok_or_else(|| AppError::Upstream("token response had no token".into()))?;
        Ok(CachedToken::new(token, lifetime))
    }
    .await;
    tracing::debug!(success = result.is_ok(), "registry token refresh complete");
    result
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

/// Reduce `type/subtype; parameters` to the bare media type, and only when it is
/// a manifest type we support. Everything downstream (response headers, stored
/// pointers, `Accept` matching) then only ever sees one of these constants — a
/// media type read out of an upstream body can never reach a header verbatim.
fn normalized_manifest_media_type(content_type: &str) -> Option<&'static str> {
    let (essence, parameters) = match content_type.split_once(';') {
        Some((essence, parameters)) => (essence, Some(parameters)),
        None => (content_type, None),
    };
    if parameters.is_some_and(|parameters| !valid_media_type_parameters(parameters)) {
        return None;
    }
    let essence = essence.trim_matches([' ', '\t']);
    MANIFEST_MEDIA_TYPES
        .into_iter()
        .find(|known| essence.eq_ignore_ascii_case(known))
}

/// `parameter *( OWS ";" OWS parameter )` per RFC 9110, with the leading `;`
/// already consumed. Rejecting malformed parameters keeps a poisoned media type
/// from being silently accepted as its (valid) prefix.
fn valid_media_type_parameters(parameters: &str) -> bool {
    parameters.split(';').all(|parameter| {
        let parameter = parameter.trim_matches([' ', '\t']);
        let Some((name, value)) = parameter.split_once('=') else {
            return false;
        };
        let name = name.trim_end_matches([' ', '\t']);
        let value = value.trim_start_matches([' ', '\t']);
        !name.is_empty()
            && name.bytes().all(is_token_byte)
            && (is_quoted_string(value) || (!value.is_empty() && value.bytes().all(is_token_byte)))
    })
}

/// The OCI image-manifest spec makes the top-level `mediaType` OPTIONAL (ghcr.io
/// omits it), so fall back to the media type the response — or our own stored
/// metadata — declared.
fn manifest_media_type(bytes: &[u8], declared: Option<&str>) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("schemaVersion")?.as_u64() != Some(2) {
        return None;
    }
    match value.get("mediaType") {
        Some(media_type) => normalized_manifest_media_type(media_type.as_str()?),
        None => normalized_manifest_media_type(declared?),
    }
}

/// Last-resort media type for a manifest read back out of the cache. A backend
/// that cannot persist attributes stores no content type, and a by-digest pull
/// carries no tag pointer to supply one, so nothing declares the type of a body
/// that omits its own `mediaType`. An image manifest is what such a body is (the
/// OCI image spec makes the field optional and names this type for it), so infer
/// it rather than refuse a pull we can answer correctly.
///
/// Only ever for an *absent* field: a body that declares an unusable `mediaType`
/// is still rejected, never repaired.
fn inferred_cached_manifest_media_type(bytes: &[u8]) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("schemaVersion")?.as_u64() != Some(2) || value.get("mediaType").is_some() {
        return None;
    }
    (value.get("config").is_some() && value.get("layers").is_some()).then_some(MEDIA_TYPE_MANIFEST)
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

async fn read_cached_blob(blob: Blob, max_bytes: u64) -> Result<Vec<u8>, AppError> {
    upstream::read_bounded(Some(blob.meta.size), blob.data, max_bytes, AppError::from).await
}

async fn read_upstream_body(
    response: reqwest::Response,
    max_bytes: u64,
    resource: &str,
) -> Result<Vec<u8>, AppError> {
    upstream::read_response(response, max_bytes, resource).await
}

type BlobStream = BoxStream<'static, Result<Bytes, std::io::Error>>;

/// Response builders here are fed upstream metadata, and `Builder::header` defers
/// its error to `body()`, so never `expect()` the result.
fn build_response(builder: Builder, body: Body) -> Result<Response, AppError> {
    builder.body(body).map_err(|error| {
        tracing::warn!(%error, "upstream metadata was not a valid response header");
        AppError::Upstream("upstream metadata was not a valid response header".into())
    })
}

fn metered_blob_stream(data: BlobStream) -> BlobStream {
    Box::pin(data.map_ok(|chunk| {
        crate::metrics::record_blob_bytes(ProxyUpstream::Oci, ProxySource::Upstream, chunk.len());
        chunk
    }))
}

fn record_blob_cache_skip(reason: &'static str) {
    metrics::counter!("helmoci_oci_blob_cache_skips_total", "reason" => reason).increment(1);
    tracing::warn!(
        reason,
        "OCI blob exceeds the cache limit; streaming uncached"
    );
}

enum UpstreamBlob {
    Buffered(Vec<u8>),
    /// Larger than the cache limit: what was already read, plus the rest of the
    /// body, so it can still be streamed through to the client.
    Oversized {
        prefix: Vec<u8>,
        rest: BlobStream,
    },
}

/// Buffer a blob body for write-through, bounded by `max_bytes` even when the
/// upstream advertises no length (chunked transfer encoding).
async fn read_upstream_blob(
    response: reqwest::Response,
    max_bytes: u64,
) -> Result<UpstreamBlob, AppError> {
    let mut data = Box::pin(response.bytes_stream());
    let mut prefix: Vec<u8> = Vec::new();
    while let Some(chunk) = data.next().await {
        let mut chunk = chunk.map_err(|error| {
            AppError::Upstream(format!(
                "reading upstream blob failed: {}",
                error.without_url()
            ))
        })?;
        let room =
            usize::try_from(max_bytes.saturating_sub(prefix.len() as u64)).unwrap_or(usize::MAX);
        if chunk.len() > room {
            let tail = chunk.split_off(room);
            prefix.extend_from_slice(&chunk);
            let rest = futures::stream::once(async move { Ok(tail) }).chain(data);
            return Ok(UpstreamBlob::Oversized {
                prefix,
                rest: Box::pin(rest.map_err(std::io::Error::other)),
            });
        }
        prefix.extend_from_slice(&chunk);
    }
    Ok(UpstreamBlob::Buffered(prefix))
}

#[derive(Debug)]
struct CorruptCachedBlob;

impl std::fmt::Display for CorruptCachedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cached blob did not hash to the requested digest")
    }
}

impl std::error::Error for CorruptCachedBlob {}

fn record_cached_blob_corruption() {
    metrics::counter!("helmoci_oci_blob_cache_corruptions_total").increment(1);
    tracing::error!("cached OCI blob failed digest verification mid-stream");
}

struct VerifyingBlob {
    data: BoxStream<'static, Result<Bytes, StorageError>>,
    hasher: Sha256,
    /// The most recent chunk, withheld until the one after it arrives. Erroring
    /// out after the body's last byte is not enough: `Content-Length` would
    /// already be satisfied, and a client (or hyper's encoder) is entitled to
    /// treat the body as complete and never look at the failure. Holding one
    /// chunk back means a corrupt entry always ends short of what it promised.
    held: Option<Bytes>,
}

/// Hashes a cached blob as it streams, so an entry too large to buffer is verified
/// too, one chunk of lookahead behind. There is no falling back to the upstream
/// here — the response has already started — so a mismatch drops the final chunk
/// and ends the body in an error instead of passing corrupt bytes off as the
/// requested digest.
fn verified_cached_blob(digest: &Digest, blob: Blob) -> Blob {
    let expected = digest.as_str().to_string();
    let start = VerifyingBlob {
        data: blob.data,
        hasher: Sha256::new(),
        held: None,
    };
    let data = futures::stream::unfold(Some(start), move |state| {
        let expected = expected.clone();
        async move {
            let VerifyingBlob {
                mut data,
                mut hasher,
                mut held,
            } = state?;
            loop {
                match data.next().await {
                    Some(Ok(chunk)) => {
                        hasher.update(&chunk);
                        if let Some(previous) = held.replace(chunk) {
                            let next = VerifyingBlob { data, hasher, held };
                            return Some((Ok(previous), Some(next)));
                        }
                    }
                    Some(Err(error)) => return Some((Err(error), None)),
                    None => {
                        let computed = format!("sha256:{}", hex::encode(hasher.finalize()));
                        if computed != expected {
                            record_cached_blob_corruption();
                            let error =
                                StorageError::backend(StorageOp::BlobRead, CorruptCachedBlob);
                            return Some((Err(error), None));
                        }
                        return held.map(|last| (Ok(last), None));
                    }
                }
            }
        }
    });
    Blob {
        meta: blob.meta,
        data: Box::pin(data),
    }
}

/// Serve a blob out of storage, verified against the requested digest either way.
/// Entries up to `MAX_BUFFERED_CACHED_BLOB_BYTES` are buffered first, so a corrupt
/// one returns `None` and the caller falls back to the upstream. Larger entries are
/// verified while streaming instead of being held in memory.
async fn cached_blob_response(digest: &Digest, blob: Blob, head_only: bool) -> Option<Response> {
    let content_type = blob
        .meta
        .content_type
        .clone()
        .unwrap_or_else(|| OCTET_STREAM_MEDIA_TYPE.to_string());
    if blob.meta.size > MAX_BUFFERED_CACHED_BLOB_BYTES {
        return Some(blob_response(
            &content_type,
            digest,
            verified_cached_blob(digest, blob),
            head_only,
            ProxyUpstream::Oci,
            ProxySource::PersistentCache,
        ));
    }
    let bytes = read_cached_blob(blob, MAX_BUFFERED_CACHED_BLOB_BYTES)
        .await
        .ok()?;
    (Digest::sha256(&bytes) == *digest).then(|| {
        blob_bytes_response(
            &content_type,
            digest,
            bytes,
            head_only,
            ProxyUpstream::Oci,
            ProxySource::PersistentCache,
        )
    })
}

fn is_token_byte(byte: u8) -> bool {
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

/// RFC 9110 `quoted-string`, restricted to printable ASCII and without the angle
/// brackets that delimit a `Link` target.
fn is_quoted_string(value: &str) -> bool {
    let bytes = value.as_bytes();
    // Length 3 is the shortest non-empty quoted string; `""` stays rejected.
    if bytes.len() < 3 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return false;
    }
    let end = bytes.len() - 1;
    let mut position = 1;
    while position < end {
        match bytes[position] {
            b'\\' => {
                position += 1;
                if position >= end || !is_quotable(bytes[position]) {
                    return false;
                }
            }
            b'"' => return false,
            byte if !is_quotable(byte) => return false,
            _ => {}
        }
        position += 1;
    }
    true
}

fn is_quotable(byte: u8) -> bool {
    matches!(byte, b' '..=b'~') && !matches!(byte, b'<' | b'>')
}

/// Split a `Link` parameter suffix (the text after the closing `>`, minus its
/// leading `;`) into parameters, honouring quoted strings.
fn split_link_params(params: &str) -> Vec<&str> {
    let bytes = params.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut position = 0;
    let mut in_quotes = false;
    while position < bytes.len() {
        match bytes[position] {
            b'"' => in_quotes = !in_quotes,
            b'\\' if in_quotes => position += 1,
            b';' if !in_quotes => {
                parts.push(&params[start..position]);
                start = position + 1;
            }
            _ => {}
        }
        position += 1;
    }
    parts.push(&params[start..]);
    parts
}

fn valid_link_params(params: &str) -> bool {
    let params = params.trim_matches([' ', '\t']);
    if params.is_empty() {
        return true;
    }
    let Some(params) = params.strip_prefix(';') else {
        return false;
    };
    split_link_params(params).into_iter().all(valid_link_param)
}

fn valid_link_param(parameter: &str) -> bool {
    let parameter = parameter.trim_matches([' ', '\t']);
    let (name, value) = match parameter.split_once('=') {
        Some((name, value)) => (
            name.trim_end_matches([' ', '\t']),
            Some(value.trim_matches([' ', '\t'])),
        ),
        None => (parameter, None),
    };
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return false;
    }
    match value {
        // RFC 8288 allows valueless extension parameters.
        None => true,
        Some(value) => {
            is_quoted_string(value) || (!value.is_empty() && value.bytes().all(is_token_byte))
        }
    }
}

fn unquote_link_value(value: &str) -> String {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return value.to_string();
    };
    let mut unquoted = String::with_capacity(inner.len());
    let mut escaped = false;
    for character in inner.chars() {
        match character {
            '\\' if !escaped => escaped = true,
            _ => {
                escaped = false;
                unquoted.push(character);
            }
        }
    }
    unquoted
}

/// True when the first `rel` parameter names the `next` relation. Relation types
/// are a whitespace-separated list and are case-insensitive.
fn is_next_link(params: &str) -> bool {
    let params = params.trim_matches([' ', '\t']);
    let Some(params) = params.strip_prefix(';') else {
        return false;
    };
    split_link_params(params)
        .into_iter()
        .find_map(|parameter| {
            let (name, value) = parameter.trim_matches([' ', '\t']).split_once('=')?;
            name.trim_end_matches([' ', '\t'])
                .eq_ignore_ascii_case("rel")
                .then(|| unquote_link_value(value.trim_matches([' ', '\t'])))
        })
        .is_some_and(|rel| {
            rel.split_ascii_whitespace()
                .any(|relation| relation.eq_ignore_ascii_case("next"))
        })
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

fn is_rfc_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn is_strict_tag_link_reference(reference: &str, target: &OciTarget) -> bool {
    let first_segment_end = reference.find(['/', '?', '#']).unwrap_or(reference.len());
    let first_segment = &reference[..first_segment_end];
    let Some(scheme_end) = first_segment.find(':') else {
        return !reference.starts_with("//");
    };
    let scheme = &reference[..scheme_end];
    let remainder = &reference[scheme_end + 1..];
    let expected_scheme = if target.plain_http { "http" } else { "https" };
    if !is_rfc_scheme(scheme)
        || !scheme.eq_ignore_ascii_case(expected_scheme)
        || !remainder.starts_with("//")
    {
        return false;
    }
    !matches!(remainder.as_bytes().get(2), None | Some(b'/' | b'?' | b'#'))
}

fn resolved_tag_link_url(reference: &str, target: &OciTarget) -> Option<url::Url> {
    if !is_safe_uri_reference(reference) || !is_strict_tag_link_reference(reference, target) {
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

/// One RFC 8288 link-value: the target inside `<>` plus its parameter suffix,
/// kept verbatim so a rewritten header carries the upstream's parameters.
struct LinkValue<'a> {
    uri: &'a str,
    params: &'a str,
}

/// Parse a `Link` field value, which may legally carry several comma-separated
/// link-values. Fails closed: any syntax we cannot fully interpret rejects the
/// whole field rather than guessing at it.
fn parse_link_field<'a>(field: &'a str) -> Option<Vec<LinkValue<'a>>> {
    // Only what a header field can legally carry, which also keeps the byte
    // offsets below on character boundaries.
    if !field
        .bytes()
        .all(|byte| matches!(byte, b' '..=b'~' | b'\t'))
    {
        return None;
    }
    let bytes = field.as_bytes();
    let mut links = Vec::new();
    let mut position = 0;
    loop {
        // OWS plus the empty list elements RFC 9110 list syntax tolerates.
        while matches!(bytes.get(position), Some(b' ' | b'\t' | b',')) {
            position += 1;
        }
        if position == bytes.len() {
            return Some(links);
        }
        if bytes.get(position) != Some(&b'<') {
            return None;
        }
        position += 1;
        let uri_start = position;
        while !matches!(bytes.get(position), None | Some(b'>')) {
            position += 1;
        }
        if bytes.get(position) != Some(&b'>') {
            return None;
        }
        let uri = &field[uri_start..position];
        position += 1;

        let params_start = position;
        let mut in_quotes = false;
        while let Some(byte) = bytes.get(position) {
            match byte {
                b'"' => in_quotes = !in_quotes,
                b'\\' if in_quotes => position += 1,
                b',' if !in_quotes => break,
                _ => {}
            }
            position += 1;
        }
        if in_quotes || position > bytes.len() {
            return None;
        }
        let params = field[params_start..position].trim_end_matches([' ', '\t']);
        if !valid_link_params(params) {
            return None;
        }
        links.push(LinkValue { uri, params });
    }
}

/// Rewrite an upstream tag-list link into the path-relative proxy form. The
/// emitted target is always `</v2/{full_name}/tags/list{?query}>`, so a malicious
/// upstream can never point a client at another host.
fn rewrite_link_value(link: &LinkValue<'_>, target: &OciTarget) -> Option<String> {
    let resolved = resolved_tag_link_url(link.uri, target)?;
    let query = resolved.query().unwrap_or_default();
    let suffix = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    Some(format!(
        "</v2/{}/tags/list{}>{}",
        target.full_name, suffix, link.params
    ))
}

fn count_tag_link_drop(reason: &'static str) {
    metrics::counter!("helmoci_oci_tag_link_drops_total", "reason" => reason).increment(1);
}

fn drop_tag_link(reason: &'static str) -> Option<String> {
    count_tag_link_drop(reason);
    tracing::warn!(reason, "dropping upstream tag pagination Link header");
    None
}

/// Exactly one `rel="next"` link may be rewritten: zero means there is no next
/// page, and several are contradictory, so both fail closed.
fn select_next_link<'a>(links: &'a [LinkValue<'a>]) -> Option<&'a LinkValue<'a>> {
    let mut candidates = links.iter().filter(|link| is_next_link(link.params));
    let Some(next) = candidates.next() else {
        // Normal on the last page, so it is counted but not warned about.
        count_tag_link_drop("no_next_relation");
        tracing::debug!("upstream tag Link header had no next relation");
        return None;
    };
    if candidates.next().is_some() {
        drop_tag_link("ambiguous_next_relation");
        return None;
    }
    Some(next)
}

/// Rewrite the `rel="next"` link across every `Link` field of one response.
fn rewrite_tag_links(fields: &[&str], target: &OciTarget) -> Option<String> {
    if fields.is_empty() {
        return None;
    }
    let mut links = Vec::new();
    for field in fields {
        let Some(parsed) = parse_link_field(field) else {
            return drop_tag_link("unparsable_field");
        };
        links.extend(parsed);
    }
    let next = select_next_link(&links)?;
    rewrite_link_value(next, target).or_else(|| drop_tag_link("unsafe_reference"))
}

fn rewrite_upstream_tag_link(response: &reqwest::Response, target: &OciTarget) -> Option<String> {
    let mut fields = Vec::new();
    for value in response.headers().get_all(header::LINK) {
        let Ok(field) = value.to_str() else {
            return drop_tag_link("undecodable_field");
        };
        fields.push(field);
    }
    rewrite_tag_links(&fields, target)
}

async fn cached_manifest_response(
    digest: &Digest,
    blob: Blob,
    head_only: bool,
    declared: Option<&str>,
) -> Result<Response, AppError> {
    let stored_media_type = blob.meta.content_type.clone();
    let bytes = read_cached_blob(blob, MAX_MANIFEST_BYTES).await?;
    if Digest::sha256(&bytes) != *digest {
        return Err(AppError::ManifestUnknown(format!(
            "manifest unknown: {digest}"
        )));
    }
    let declared = stored_media_type.as_deref().or(declared);
    let media_type = manifest_media_type(&bytes, declared)
        .or_else(|| inferred_cached_manifest_media_type(&bytes));
    let Some(media_type) = media_type else {
        return Err(AppError::ManifestUnknown(format!(
            "manifest unknown: {digest}"
        )));
    };
    Ok(bytes_response(media_type, digest, bytes, head_only))
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
    let kind = if suffix.starts_with("blobs/") {
        UpstreamKind::OciBlob
    } else if suffix.starts_with("tags/list") {
        UpstreamKind::OciTags
    } else {
        UpstreamKind::OciManifest
    };
    let cache_key = upstream_token_cache_key(target);
    let build_headers = |token: Option<String>| {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(accept) = accept {
            let value = reqwest::header::HeaderValue::from_str(accept)
                .map_err(|_| AppError::Upstream("invalid upstream Accept header".into()))?;
            headers.insert(reqwest::header::ACCEPT, value);
        }
        if let Some(token) = token {
            let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| AppError::Upstream("invalid upstream bearer token".into()))?;
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
        Ok::<_, AppError>(headers)
    };

    let cached = state.upstream_tokens.get(&cache_key).await;
    let cached = cached
        .as_ref()
        .and_then(CachedToken::live)
        .map(str::to_string);
    let response = upstream::send(
        state,
        method.clone(),
        url.clone(),
        build_headers(cached)?,
        InitialClient::Trusted,
        true,
        kind,
    )
    .await?;
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
    let bearer = token.token.clone();
    state.upstream_tokens.insert(cache_key, token).await;
    upstream::send(
        state,
        method,
        url,
        build_headers(Some(bearer))?,
        InitialClient::Trusted,
        true,
        kind,
    )
    .await
}

pub async fn manifest(
    state: &AppState,
    proxy_host: &str,
    target: OciTarget,
    reference: &str,
    head_only: bool,
    accept: Option<String>,
) -> Result<Response, AppError> {
    if target.store {
        if let Some(digest) = Digest::parse(reference) {
            if let Some(blob) = state.storage.get_blob(&digest).await? {
                let result = cached_manifest_response(&digest, blob, head_only, None).await;
                if let Ok(response) = result {
                    metrics::counter!("helmoci_oci_manifest_cache_hits_total").increment(1);
                    tracing::debug!(kind = "manifest", "OCI cache hit");
                    crate::metrics::record_proxy_response(
                        ProxyKind::Manifest,
                        ProxyUpstream::Oci,
                        ProxySource::PersistentCache,
                    );
                    return Ok(response);
                }
                metrics::counter!("helmoci_oci_manifest_cache_misses_total").increment(1);
                tracing::debug!(kind = "manifest", "OCI cache miss");
                return result;
            }
        } else {
            let scope = TagScope {
                proxy_host,
                full_name: &target.full_name,
            };
            if let Some(pointer) = state.storage.get_tag_pointer(&scope, reference).await?
                && let Some(pointer_media_type) =
                    normalized_manifest_media_type(&pointer.media_type)
                && accepts_media_type(accept.as_deref(), pointer_media_type)
                && let Some(blob) = state.storage.get_blob(&pointer.digest).await?
            {
                let result = cached_manifest_response(
                    &pointer.digest,
                    blob,
                    head_only,
                    Some(pointer_media_type),
                )
                .await;
                if let Ok(response) = result {
                    metrics::counter!("helmoci_oci_manifest_cache_hits_total").increment(1);
                    tracing::debug!(kind = "manifest", "OCI cache hit");
                    crate::metrics::record_proxy_response(
                        ProxyKind::Manifest,
                        ProxyUpstream::Oci,
                        ProxySource::PersistentCache,
                    );
                    return Ok(response);
                }
                metrics::counter!("helmoci_oci_manifest_cache_misses_total").increment(1);
                tracing::debug!(kind = "manifest", "OCI cache miss");
                return result;
            }
        }
        metrics::counter!("helmoci_oci_manifest_cache_misses_total").increment(1);
        tracing::debug!(kind = "manifest", "OCI cache miss");
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
    let declared_media_type = normalized_manifest_media_type(&content_type);

    if head_only {
        // No body to inspect, so the declared media type is all a HEAD has: an
        // unsupported one cannot be answered honestly.
        let Some(declared_media_type) = declared_media_type else {
            return Err(AppError::Upstream(
                "upstream response was not a supported OCI manifest media type".into(),
            ));
        };
        // A HEAD cannot recompute Content-Length or ETag from the body without
        // fetching it, which is the one thing HEAD exists to avoid, so those two
        // are forwarded as the upstream reported them. The digest is checkable
        // though: junk is dropped and a digest request answered with a different
        // digest is rejected outright.
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, declared_media_type)
            .header("Docker-Distribution-API-Version", "registry/2.0");
        if let Some(length) = response.content_length() {
            builder = builder.header(header::CONTENT_LENGTH, length);
        }
        if let Some(digest) = header_str(&response, "docker-content-digest")
            .as_deref()
            .and_then(Digest::parse)
        {
            if Digest::parse(reference).is_some_and(|requested| requested != digest) {
                return Err(AppError::Upstream(format!(
                    "upstream reported digest {digest} for a different requested digest"
                )));
            }
            builder = builder.header("Docker-Content-Digest", digest.as_str());
        }
        if let Some(etag) = header_str(&response, "etag") {
            builder = builder.header(header::ETAG, etag);
        }
        let response = build_response(builder, Body::empty())?;
        crate::metrics::record_proxy_response(
            ProxyKind::Manifest,
            ProxyUpstream::Oci,
            ProxySource::Upstream,
        );
        return Ok(response);
    }

    let bytes = read_upstream_body(response, MAX_MANIFEST_BYTES, "manifest").await?;
    let digest = Digest::sha256(&bytes);
    if let Some(requested_digest) = Digest::parse(reference)
        && requested_digest != digest
    {
        return Err(AppError::Upstream(format!(
            "upstream manifest bytes did not match requested digest {requested_digest}"
        )));
    }
    let Some(media_type) = manifest_media_type(&bytes, declared_media_type) else {
        return Err(AppError::Upstream(
            "upstream response was not a supported OCI manifest".into(),
        ));
    };
    if target.store {
        state
            .storage
            .put_blob(&digest, media_type, bytes.clone().into())
            .await?;
        if Digest::parse(reference).is_none() {
            let scope = TagScope {
                proxy_host,
                full_name: &target.full_name,
            };
            let pointer = TagPointer {
                digest: digest.clone(),
                media_type: media_type.to_string(),
                size: bytes.len() as u64,
            };
            state
                .storage
                .put_tag_pointer(&scope, reference, &pointer)
                .await?;
        }
    }
    let response = bytes_response(media_type, &digest, bytes.to_vec(), false);
    crate::metrics::record_proxy_response(
        ProxyKind::Manifest,
        ProxyUpstream::Oci,
        ProxySource::Upstream,
    );
    Ok(response)
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
        && let Some(response) = cached_blob_response(&digest, blob, head_only).await
    {
        metrics::counter!("helmoci_oci_blob_cache_hits_total").increment(1);
        tracing::debug!(kind = "blob", "OCI cache hit");
        crate::metrics::record_proxy_response(
            ProxyKind::Blob,
            ProxyUpstream::Oci,
            ProxySource::PersistentCache,
        );
        return Ok(response);
    }
    if target.store {
        metrics::counter!("helmoci_oci_blob_cache_misses_total").increment(1);
        tracing::debug!(kind = "blob", "OCI cache miss");
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
        .unwrap_or_else(|| OCTET_STREAM_MEDIA_TYPE.to_string());
    let etag = header_str(&response, "etag");
    let advertised_length = response.content_length();
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &content_type)
        .header("Docker-Content-Digest", digest.as_str())
        .header("Docker-Distribution-API-Version", "registry/2.0");
    if head_only {
        // Content-Length and ETag are the upstream's word: a HEAD cannot verify
        // them without fetching the body it exists to avoid. The digest is the
        // one the client asked for, so it is exact.
        if let Some(length) = advertised_length {
            builder = builder.header(header::CONTENT_LENGTH, length);
        }
        if let Some(etag) = etag {
            builder = builder.header(header::ETAG, etag);
        }
        let response = build_response(builder, Body::empty())?;
        crate::metrics::record_proxy_response(
            ProxyKind::Blob,
            ProxyUpstream::Oci,
            ProxySource::Upstream,
        );
        return Ok(response);
    }

    let cache_limit = state.cfg.settings.max_chart_bytes;
    // A chunked upstream advertises no length, which must not silently disable
    // write-through: buffer up to the cap and only give up if it is exceeded.
    if target.store {
        if advertised_length.is_some_and(|length| length > cache_limit) {
            record_blob_cache_skip("advertised_over_limit");
        } else {
            match read_upstream_blob(response, cache_limit).await? {
                UpstreamBlob::Buffered(bytes) => {
                    if Digest::sha256(&bytes) != digest {
                        return Err(AppError::Upstream(format!(
                            "upstream blob bytes did not match requested digest {digest}"
                        )));
                    }
                    state
                        .storage
                        .put_blob(&digest, &content_type, bytes.clone().into())
                        .await?;
                    let response = blob_bytes_response(
                        &content_type,
                        &digest,
                        bytes,
                        false,
                        ProxyUpstream::Oci,
                        ProxySource::Upstream,
                    );
                    crate::metrics::record_proxy_response(
                        ProxyKind::Blob,
                        ProxyUpstream::Oci,
                        ProxySource::Upstream,
                    );
                    return Ok(response);
                }
                UpstreamBlob::Oversized { prefix, rest } => {
                    record_blob_cache_skip("streamed_over_limit");
                    // The advertised length (if any) still describes the whole body.
                    if let Some(length) = advertised_length {
                        builder = builder.header(header::CONTENT_LENGTH, length);
                    }
                    if let Some(etag) = etag {
                        builder = builder.header(header::ETAG, etag);
                    }
                    let prefix = futures::stream::once(async move { Ok(Bytes::from(prefix)) });
                    let response = build_response(
                        builder,
                        Body::from_stream(metered_blob_stream(Box::pin(prefix.chain(rest)))),
                    )?;
                    crate::metrics::record_proxy_response(
                        ProxyKind::Blob,
                        ProxyUpstream::Oci,
                        ProxySource::Upstream,
                    );
                    return Ok(response);
                }
            }
        }
    }
    if let Some(length) = advertised_length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    if let Some(etag) = etag {
        builder = builder.header(header::ETAG, etag);
    }
    let data = metered_blob_stream(Box::pin(
        response.bytes_stream().map_err(std::io::Error::other),
    ));
    let response = build_response(builder, Body::from_stream(data))?;
    crate::metrics::record_proxy_response(
        ProxyKind::Blob,
        ProxyUpstream::Oci,
        ProxySource::Upstream,
    );
    Ok(response)
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
            "upstream registry returned HTTP {} for tag list",
            response.status().as_u16()
        )));
    }
    let link = rewrite_upstream_tag_link(&response, &target);
    let bytes = read_upstream_body(response, MAX_TAG_LIST_BYTES, "tag list").await?;
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
        match axum::http::HeaderValue::from_str(&link) {
            Ok(value) => builder = builder.header(header::LINK, value),
            Err(_) => {
                drop_tag_link("invalid_header_value");
            }
        }
    }
    let body = if head_only {
        Body::empty()
    } else {
        Body::from(body)
    };
    let response = build_response(builder, body)?;
    crate::metrics::record_proxy_response(
        ProxyKind::Tags,
        ProxyUpstream::Oci,
        ProxySource::Upstream,
    );
    Ok(response)
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
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

    struct NoAuthHeader;

    impl Match for NoAuthHeader {
        fn matches(&self, request: &Request) -> bool {
            !request.headers.contains_key("authorization")
        }
    }

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

    /// One `Link` field value, the single-field shape most upstreams send.
    fn rewrite_tag_link(field: &str, target: &OciTarget) -> Option<String> {
        rewrite_tag_links(&[field], target)
    }

    #[test]
    fn manifest_media_types_are_normalized_to_known_constants() {
        assert_eq!(
            normalized_manifest_media_type("application/vnd.oci.image.manifest.v1+json"),
            Some(MEDIA_TYPE_MANIFEST)
        );
        assert_eq!(
            normalized_manifest_media_type(
                "APPLICATION/VND.OCI.IMAGE.MANIFEST.V1+JSON; charset=utf-8"
            ),
            Some(MEDIA_TYPE_MANIFEST)
        );
        assert_eq!(
            normalized_manifest_media_type(
                "application/vnd.oci.image.index.v1+json ;charset=\"utf-8\""
            ),
            Some(OCI_INDEX_MEDIA_TYPE)
        );
        for poisoned in [
            "application/vnd.oci.image.manifest.v1+json;\u{1}",
            "application/vnd.oci.image.manifest.v1+json\u{7f}",
            "application/vnd.oci.image.manifest.v1+json; charset=\"un\u{7f}quoted",
            "application/vnd.oci.image.manifest.v1+json; charset",
            "application/vnd.oci.image.manifest.v1+json; =utf-8",
            "application/json",
            "",
        ] {
            assert_eq!(
                normalized_manifest_media_type(poisoned),
                None,
                "{poisoned:?}"
            );
        }
    }

    #[test]
    fn manifest_media_type_falls_back_to_the_declared_type() {
        let with_media_type =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}"#;
        let without_media_type = br#"{"schemaVersion":2,"config":{},"layers":[]}"#;
        assert_eq!(
            manifest_media_type(with_media_type, Some(MEDIA_TYPE_MANIFEST)),
            Some(OCI_INDEX_MEDIA_TYPE),
            "the body wins over the declared type"
        );
        assert_eq!(
            manifest_media_type(without_media_type, Some(MEDIA_TYPE_MANIFEST)),
            Some(MEDIA_TYPE_MANIFEST)
        );
        assert_eq!(manifest_media_type(without_media_type, None), None);
        assert_eq!(
            manifest_media_type(without_media_type, Some("application/json")),
            None
        );
        assert_eq!(
            manifest_media_type(
                br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json;"}"#,
                Some(MEDIA_TYPE_MANIFEST)
            ),
            None,
            "a poisoned body media type is rejected, never repaired"
        );
        assert_eq!(
            manifest_media_type(br#"{"schemaVersion":1}"#, Some(MEDIA_TYPE_MANIFEST)),
            None
        );
        assert_eq!(
            manifest_media_type(b"not-json", Some(MEDIA_TYPE_MANIFEST)),
            None
        );
        assert_eq!(
            manifest_media_type(
                br#"{"schemaVersion":2,"mediaType":2}"#,
                Some(MEDIA_TYPE_MANIFEST)
            ),
            None
        );
    }

    /// The cache-only fallback: it fills in an absent `mediaType`, and nothing else.
    #[test]
    fn cached_manifest_media_type_is_only_inferred_when_the_field_is_absent() {
        assert_eq!(
            inferred_cached_manifest_media_type(br#"{"schemaVersion":2,"config":{},"layers":[]}"#),
            Some(MEDIA_TYPE_MANIFEST)
        );
        for rejected in [
            // Present but unusable: rejected, never repaired.
            br#"{"schemaVersion":2,"mediaType":"application/json","config":{},"layers":[]}"#.as_slice(),
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json;","config":{},"layers":[]}"#,
            br#"{"schemaVersion":2,"mediaType":null,"config":{},"layers":[]}"#,
            // Not an image manifest, so there is nothing to infer.
            br#"{"schemaVersion":2}"#,
            br#"{"schemaVersion":2,"config":{}}"#,
            br#"{"schemaVersion":2,"manifests":[]}"#,
            br#"{"schemaVersion":1,"config":{},"layers":[]}"#,
            b"not-a-manifest",
        ] {
            assert_eq!(
                inferred_cached_manifest_media_type(rejected),
                None,
                "{:?}",
                String::from_utf8_lossy(rejected)
            );
        }
    }

    /// The premise of the chunked write-through test: a chunked upstream response
    /// advertises no length, which must not disable caching.
    #[tokio::test]
    async fn chunked_upstream_blobs_advertise_no_length_but_still_buffer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/x/blobs/chunked"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("transfer-encoding", "chunked")
                    .set_body_string("chunked-body"),
            )
            .mount(&server)
            .await;
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let response = send_upstream(
            &state(),
            &target,
            reqwest::Method::GET,
            "blobs/chunked",
            None,
        )
        .await
        .unwrap();
        assert_eq!(response.content_length(), None);

        let buffered = read_upstream_blob(response, 1024).await.unwrap();
        let UpstreamBlob::Buffered(bytes) = buffered else {
            panic!("a short chunked body must be buffered for write-through");
        };
        assert_eq!(bytes, b"chunked-body");
    }

    #[tokio::test]
    async fn oversized_upstream_blobs_keep_streaming_from_where_buffering_stopped() {
        let server = MockServer::start().await;
        let body = "0123456789abcdef";
        Mock::given(method("GET"))
            .and(path("/v2/x/blobs/big"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );
        let response = send_upstream(&state(), &target, reqwest::Method::GET, "blobs/big", None)
            .await
            .unwrap();

        let UpstreamBlob::Oversized { prefix, rest } =
            read_upstream_blob(response, 4).await.unwrap()
        else {
            panic!("a body over the limit must not be buffered whole");
        };
        assert_eq!(prefix, b"0123");
        let rest: Vec<u8> = rest
            .try_fold(Vec::new(), |mut all, chunk| async move {
                all.extend_from_slice(&chunk);
                Ok(all)
            })
            .await
            .unwrap();
        assert_eq!(rest, b"456789abcdef");
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
    fn tag_links_require_the_target_origin() {
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
        for (link, expected) in [
            (
                "<HTTPS://registry.example/v2/x/tags/list?n=one>; rel=next",
                "</v2/alias/x/tags/list?n=one>; rel=next",
            ),
            (
                "<https://registry.example:443/v2/x/tags/list?n=one>; rel=next",
                "</v2/alias/x/tags/list?n=one>; rel=next",
            ),
            (
                "<?n=one,two>; rel=next",
                "</v2/alias/x/tags/list?n=one,two>; rel=next",
            ),
            (
                "<./list?n=one>; rel=next",
                "</v2/alias/x/tags/list?n=one>; rel=next",
            ),
        ] {
            assert_eq!(
                rewrite_tag_link(link, &target),
                Some(expected.into()),
                "{link}"
            );
        }
        for link in [
            "<http://registry.example/v2/x/tags/list?n=1>; rel=next",
            "<https://registry.example:444/v2/x/tags/list?n=1>; rel=next",
            "<https://foreign.example/v2/x/tags/list?n=1>; rel=next",
        ] {
            assert_eq!(rewrite_tag_link(link, &target), None, "{link}");
        }
    }

    /// RFC 8288 allows several comma-separated link-values per field, and several
    /// `Link` fields per response: the `next` relation is selected out of them.
    #[test]
    fn tag_links_select_the_next_relation_across_values_and_fields() {
        let target = target("registry.example", UpstreamAuthKind::None, false);
        let next = "</v2/x/tags/list?n=2&last=b>; rel=\"next\"";
        let previous = "</v2/x/tags/list?n=2&last=a>; rel=\"prev\"";
        let rewritten = "</v2/alias/x/tags/list?n=2&last=b>; rel=\"next\"";
        assert_eq!(
            rewrite_tag_link(&format!("{next}, {previous}"), &target),
            Some(rewritten.into())
        );
        assert_eq!(
            rewrite_tag_link(&format!("{previous}, {next}"), &target),
            Some(rewritten.into())
        );
        assert_eq!(
            rewrite_tag_links(&[previous, next], &target),
            Some(rewritten.into())
        );
        assert_eq!(
            rewrite_tag_link(
                "</v2/x/tags/list?n=2>; rel=\"prefetch NEXT\"; title=\"page\"",
                &target
            ),
            Some("</v2/alias/x/tags/list?n=2>; rel=\"prefetch NEXT\"; title=\"page\"".into())
        );
        // Fail closed: no next relation, contradictory next relations, an unsafe
        // next target, or a field we cannot parse.
        for links in [
            vec![previous],
            vec![next, next],
            vec![
                next,
                "<https://foreign.example/v2/x/tags/list?n=2>; rel=next",
            ],
            vec![
                "<https://foreign.example/v2/x/tags/list?n=2>; rel=next",
                previous,
            ],
            vec![&format!("{next}, bogus")],
            vec!["</v2/x/tags/list>; rel=next; title=\"a>, <https://evil.example/x\""],
        ] {
            assert_eq!(rewrite_tag_links(&links, &target), None, "{links:?}");
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
            format!("<{path}>; rel=next; extra=\"a>b\""),
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

    #[test]
    fn tag_links_reject_repaired_absolute_urls() {
        let https_target = target("registry.example", UpstreamAuthKind::None, false);
        let path = "/v2/x/tags/list?n=one";
        for reference in [
            format!("https:/registry.example{path}"),
            format!("https:registry.example{path}"),
            format!("https:///registry.example{path}"),
            format!("https:////registry.example{path}"),
            format!("https://///registry.example{path}"),
        ] {
            let link = format!("<{reference}>; rel=next");
            assert_eq!(rewrite_tag_link(&link, &https_target), None, "{reference}");
        }

        let plain_target = target("registry.example", UpstreamAuthKind::None, true);
        assert_eq!(
            rewrite_tag_link(
                "<http:/registry.example/v2/x/tags/list?n=one>; rel=next",
                &plain_target
            ),
            None
        );
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
                CachedToken::new("must-not-be-sent".to_string(), Some(3600)),
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
    fn reads_advertised_token_lifetimes_leniently() {
        for (value, expected) in [
            (serde_json::json!(3600), Some(3600)),
            (serde_json::json!("3600"), Some(3600)),
            (serde_json::json!(" 3600 "), Some(3600)),
            (serde_json::json!(3600.9), Some(3600)),
            (serde_json::json!(0), Some(0)),
            (serde_json::json!(-1), None),
            (serde_json::json!("soon"), None),
            (serde_json::json!(null), None),
            (serde_json::json!({}), None),
            (serde_json::json!(1e30), Some(u64::MAX)),
        ] {
            assert_eq!(
                advertised_token_lifetime(Some(&value)),
                expected,
                "{value:?}"
            );
        }
        assert_eq!(advertised_token_lifetime(None), None);
    }

    /// A token response whose `expires_in` we cannot read must still yield a
    /// token, on the default lifetime.
    #[tokio::test]
    async fn unreadable_expires_in_does_not_fail_the_token_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "odd-token",
                "expires_in": "not-a-number",
                "issued_at": "2026-08-06T00:00:00Z",
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

        assert_eq!(token.live(), Some("odd-token"));
        server.verify().await;
    }

    /// The cached token is reused while it is live: the 401 dance runs once.
    #[tokio::test]
    async fn live_cached_tokens_are_reused_across_requests() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .and(NoAuthHeader)
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!("Bearer realm=\"{}/token\"", server.uri()).as_str(),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .and(header("authorization", "Bearer live-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": "live-token", "expires_in": 3600})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let state = state();
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        for round in 0..2 {
            let response = send_upstream(
                &state,
                &target,
                reqwest::Method::GET,
                "manifests/latest",
                None,
            )
            .await
            .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK, "round {round}");
        }

        server.verify().await;
    }

    /// A token past its deadline is neither sent nor reused: the dance runs again.
    #[tokio::test]
    async fn expired_cached_tokens_are_refreshed_instead_of_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .and(header("authorization", "Bearer stale-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .and(NoAuthHeader)
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!("Bearer realm=\"{}/token\"", server.uri()).as_str(),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .and(header("authorization", "Bearer fresh-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": "fresh-token", "expires_in": 3600})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let state = state();
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );
        let cache_key = upstream_token_cache_key(&target);
        state
            .upstream_tokens
            .insert(
                cache_key.clone(),
                CachedToken::expired("stale-token".into()),
            )
            .await;

        let response = send_upstream(
            &state,
            &target,
            reqwest::Method::GET,
            "manifests/latest",
            None,
        )
        .await
        .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            state
                .upstream_tokens
                .get(&cache_key)
                .await
                .as_ref()
                .and_then(CachedToken::live),
            Some("fresh-token"),
            "the refreshed token must replace the expired entry"
        );
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

        assert_eq!(token.token, "local-token");
        assert_eq!(token.live(), Some("local-token"));
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

        assert_eq!(token.token, "anon-token");
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

        let (request, client) = build_token_request(&state, &target, &challenge)
            .await
            .unwrap();

        assert_eq!(client, InitialClient::Public);
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

    #[tokio::test]
    async fn token_response_rejects_advertised_and_streamed_bodies_over_one_mib() {
        let server = MockServer::start().await;
        let oversized = vec![b'a'; 1024 * 1024 + 1];
        Mock::given(method("GET"))
            .and(path("/advertised"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", oversized.len().to_string())
                    .set_body_bytes(oversized.clone()),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/streamed"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("transfer-encoding", "chunked")
                    .set_body_bytes(oversized),
            )
            .expect(1)
            .mount(&server)
            .await;
        let target = target(
            server.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        for path in ["advertised", "streamed"] {
            let challenge = BearerChallenge {
                realm: format!("{}/{path}", server.uri()),
                service: None,
                scope: None,
            };
            let result = fetch_token(&state(), &target, &challenge).await;
            assert!(matches!(result, Err(AppError::TooLarge(_))), "{path}");
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn configured_oci_redirect_to_private_origin_is_rejected_without_contact() {
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/private"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&private)
            .await;
        let registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/private", private.uri())),
            )
            .expect(1)
            .mount(&registry)
            .await;
        let target = target(
            registry.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let result = send_upstream(
            &state(),
            &target,
            reqwest::Method::GET,
            "manifests/latest",
            None,
        )
        .await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        registry.verify().await;
        private.verify().await;
    }

    #[tokio::test]
    async fn configured_oci_same_origin_private_redirect_is_allowed() {
        let registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/x/manifests/latest"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", "/moved"))
            .expect(1)
            .mount(&registry)
            .await;
        Mock::given(method("GET"))
            .and(path("/moved"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&registry)
            .await;
        let target = target(
            registry.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let response = send_upstream(
            &state(),
            &target,
            reqwest::Method::GET,
            "manifests/latest",
            None,
        )
        .await
        .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        registry.verify().await;
    }

    #[tokio::test]
    async fn tag_failure_error_omits_upstream_query_values() {
        let registry = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/x/tags/list"))
            .and(query_param("signature", "OCI_QUERY_SENTINEL"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&registry)
            .await;
        let target = target(
            registry.uri().trim_start_matches("http://"),
            UpstreamAuthKind::None,
            true,
        );

        let error = tags(
            &state(),
            target,
            Some("signature=OCI_QUERY_SENTINEL"),
            false,
        )
        .await
        .unwrap_err();
        let AppError::Upstream(message) = error else {
            panic!("tag failure should be an upstream error")
        };

        assert!(!message.contains("signature"), "{message}");
        assert!(!message.contains("OCI_QUERY_SENTINEL"), "{message}");
        registry.verify().await;
    }
}
