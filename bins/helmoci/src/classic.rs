use crate::error::AppError;
use crate::metrics::{ProxyKind, ProxySource, ProxyUpstream, UpstreamKind};
use crate::respond::{blob_response, bytes_response};
use crate::state::AppState;
use crate::upstream::{self, InitialClient};
use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use helmoci_core::helm::index::IndexRepo;
use helmoci_core::helm::rewrite::RewriteContext;
use helmoci_core::helm::tgz::ArchiveLimits;
use helmoci_core::oci::build::{BuiltChart, build_helm_oci_chart_with_limits};
use helmoci_core::oci::{
    Digest, MEDIA_TYPE_HELM_CHART, MEDIA_TYPE_HELM_CONFIG, MEDIA_TYPE_MANIFEST, OciManifest,
};
use helmoci_core::resolver::{ClassicChart, ClassicSource};
use helmoci_storage::{Blob, Storage, StorageError, TagScope};
use std::sync::Arc;

/// A bounded, non-secret log dimension: which resolution path produced the chart.
const fn source_label(source: ClassicSource) -> &'static str {
    match source {
        ClassicSource::ConfiguredAlias => "configured_alias",
        ClassicSource::HostPath => "host_path",
    }
}

/// Scheme, authority and path only: userinfo and the query may carry credentials or a
/// signed token, so they are dropped before the URL is named anywhere — a client-visible
/// message or an operator log line.
fn sanitized_url(url: &url::Url) -> String {
    let mut safe = url.clone();
    safe.set_query(None);
    safe.set_fragment(None);
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.to_string()
}

/// Whether an index error may name the repository it came from.
///
/// A host-path client wrote the repository host into its own reference, so naming the
/// sanitized repository back tells it nothing. An alias exists to hide its upstream,
/// which the operator may have pointed at an internal repository.
const fn index_repo(repo_url: &str, source: ClassicSource) -> IndexRepo<'_> {
    match source {
        ClassicSource::HostPath => IndexRepo::client_supplied(repo_url),
        ClassicSource::ConfiguredAlias => IndexRepo::hidden(repo_url),
    }
}

/// How an upstream is described to a client, on the same split as [`index_repo`]. The
/// sanitized URL still reaches operators through the `warn` events beside each use.
fn client_visible_upstream(safe_url: &str, source: ClassicSource) -> &str {
    match source {
        ClassicSource::HostPath => safe_url,
        ClassicSource::ConfiguredAlias => "the configured upstream for this alias",
    }
}

/// Who can act on the failure: a host-path client owns the reference it sent, while an
/// alias upstream is the operator's to fix.
const fn upstream_hint(source: ClassicSource) -> &'static str {
    match source {
        ClassicSource::HostPath => "Check the host/path in your oci:// URL.",
        ClassicSource::ConfiguredAlias => "Ask the registry operator to check the alias upstream.",
    }
}

fn parse_http_url(value: &str, resource: &str) -> Result<url::Url, AppError> {
    let url = url::Url::parse(value)
        .map_err(|_| AppError::Upstream(format!("invalid upstream {resource} URL")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(AppError::Upstream(format!(
            "invalid upstream {resource} URL"
        )));
    }
    Ok(url)
}

fn index_url(repo_url: &str) -> Result<url::Url, AppError> {
    let mut url = parse_http_url(repo_url, "repository")?;
    let path = format!("{}/index.yaml", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}

/// Both sources follow redirects: charts published from GitHub releases always
/// answer 302, and a repository behind a canonical 301/308 never reaches its
/// index.yaml otherwise. `upstream::send` re-validates every hop (public HTTPS
/// cross-origin, no HTTPS downgrade, no userinfo, credentials and cookies
/// stripped, exactly one `Location`, five hops) and the public client re-checks
/// every resolved address, so the hop after a redirect is held to the same policy
/// as the first request.
const fn classic_client(source: ClassicSource) -> (InitialClient, bool) {
    match source {
        ClassicSource::ConfiguredAlias => (InitialClient::Trusted, true),
        ClassicSource::HostPath => (InitialClient::Public, true),
    }
}

async fn send_classic(
    state: &AppState,
    url: url::Url,
    source: ClassicSource,
    headers: reqwest::header::HeaderMap,
    kind: UpstreamKind,
) -> Result<reqwest::Response, AppError> {
    let (client, redirects) = classic_client(source);
    upstream::send(
        state,
        reqwest::Method::GET,
        url,
        headers,
        client,
        redirects,
        kind,
    )
    .await
}

async fn fetch_index_text_with_source(
    state: &AppState,
    repo_url: &str,
    source: ClassicSource,
) -> Result<(Arc<String>, ProxySource), AppError> {
    let index_url = index_url(repo_url)?;
    let safe_index_url = sanitized_url(&index_url);
    let cache_prefix = match source {
        ClassicSource::ConfiguredAlias => "configured",
        ClassicSource::HostPath => "host-path",
    };
    let cache_key = format!(
        "{cache_prefix}:{}",
        Digest::sha256(index_url.as_str().as_bytes())
    );
    if let Some(text) = state.index_cache.get(&cache_key).await {
        metrics::counter!("helmoci_index_cache_hits_total").increment(1);
        tracing::debug!(source = source_label(source), "index cache hit");
        return Ok((text, ProxySource::EphemeralCache));
    }

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/yaml, text/yaml, text/plain, */*"),
    );
    let resp = send_classic(
        state,
        index_url,
        source,
        headers,
        UpstreamKind::ClassicIndex,
    )
    .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        // The sanitized URL is for operators only: a client behind an alias must not
        // learn the upstream it resolves to.
        tracing::warn!(
            kind = UpstreamKind::ClassicIndex.label(),
            source = source_label(source),
            status,
            url = %safe_index_url,
            "upstream Helm index request failed"
        );
        return Err(AppError::Upstream(format!(
            "No Helm repository at {} (index.yaml returned HTTP {status}). {}",
            client_visible_upstream(&safe_index_url, source),
            upstream_hint(source)
        )));
    }

    // index.yaml is bounded separately from a chart download: Bitnami-scale indexes
    // run past any sane chart cap, and an unreadable index is an unusable upstream
    // rather than an oversized artifact.
    let bytes = upstream::read_response(resp, state.cfg.settings.max_index_bytes, "Helm index")
        .await
        .map_err(|error| match error {
            AppError::TooLarge(message) => {
                tracing::warn!(
                    kind = UpstreamKind::ClassicIndex.label(),
                    source = source_label(source),
                    url = %safe_index_url,
                    "upstream Helm index exceeded max_index_bytes"
                );
                AppError::Upstream(format!(
                    "No usable Helm repository at {} ({message}).",
                    client_visible_upstream(&safe_index_url, source)
                ))
            }
            other => other,
        })?;
    let text = Arc::new(
        String::from_utf8(bytes)
            .map_err(|_| AppError::Upstream("upstream Helm index was not valid UTF-8".into()))?,
    );
    state.index_cache.insert(cache_key, text.clone()).await;
    metrics::counter!("helmoci_index_cache_misses_total").increment(1);
    tracing::debug!(source = source_label(source), "index cache miss");
    Ok((text, ProxySource::Upstream))
}

pub async fn fetch_index_text(
    state: &AppState,
    repo_url: &str,
    source: ClassicSource,
) -> Result<Arc<String>, AppError> {
    Ok(fetch_index_text_with_source(state, repo_url, source)
        .await?
        .0)
}

/// Download a chart tgz, enforcing max_chart_bytes while streaming.
pub async fn download_chart(
    state: &AppState,
    chart_url: &str,
    repo_url: &str,
    source: ClassicSource,
) -> Result<Vec<u8>, AppError> {
    let max = state.cfg.settings.max_chart_bytes;
    let chart_url = parse_http_url(chart_url, "chart")?;
    let safe_chart_url = sanitized_url(&chart_url);
    let (client, redirects) = match source {
        ClassicSource::HostPath => classic_client(source),
        ClassicSource::ConfiguredAlias => {
            let repo_url = parse_http_url(repo_url, "repository")?;
            if repo_url.origin() == chart_url.origin() {
                (InitialClient::Trusted, true)
            } else {
                upstream::validate_public_https(&chart_url)?;
                (InitialClient::Public, true)
            }
        }
    };
    let resp = upstream::send(
        state,
        reqwest::Method::GET,
        chart_url,
        reqwest::header::HeaderMap::new(),
        client,
        redirects,
        UpstreamKind::ClassicChart,
    )
    .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        tracing::warn!(
            kind = UpstreamKind::ClassicChart.label(),
            source = source_label(source),
            status,
            url = %safe_chart_url,
            "upstream chart download failed"
        );
        return Err(AppError::Upstream(format!(
            "Could not download the chart from {} (HTTP {status}). {}",
            client_visible_upstream(&safe_chart_url, source),
            upstream_hint(source)
        )));
    }
    upstream::read_response(resp, max, "chart").await
}

fn backend(state: &AppState, ephemeral: bool) -> Arc<dyn Storage> {
    if ephemeral {
        state.ephemeral.clone()
    } else {
        state.storage.clone()
    }
}

/// Look in persistent storage first, then the ephemeral cache.
async fn find_blob(
    state: &AppState,
    digest: &Digest,
) -> Result<Option<(Blob, ProxySource)>, AppError> {
    if let Some(blob) = state
        .storage
        .get_blob(digest)
        .await
        .map_err(|error| storage_failure("blob read", error))?
    {
        return Ok(Some((blob, ProxySource::PersistentCache)));
    }
    Ok(state
        .ephemeral
        .get_blob(digest)
        .await
        .map_err(|error| storage_failure("blob read", error))?
        .map(|blob| (blob, ProxySource::EphemeralCache)))
}

fn valid_helm_manifest(bytes: &[u8]) -> bool {
    let Ok(manifest) = serde_json::from_slice::<OciManifest>(bytes) else {
        return false;
    };
    manifest.schema_version == 2
        && manifest.media_type == MEDIA_TYPE_MANIFEST
        && manifest.config.media_type == MEDIA_TYPE_HELM_CONFIG
        && !manifest.layers.is_empty()
        && manifest
            .layers
            .iter()
            .all(|layer| layer.media_type == MEDIA_TYPE_HELM_CHART)
}

/// A storage failure is an outage, not a missing object: it must not be reported as
/// a permanent 404 nor swallowed into a silent upstream rebuild.
fn storage_failure(operation: &'static str, error: StorageError) -> AppError {
    tracing::warn!(operation, "classic storage read failed");
    AppError::from(error)
}

/// Serve a cached manifest blob addressed by `digest`.
///
/// The stored content type is deliberately not checked. It is metadata the format
/// never required: `local` storage cannot persist attributes at all, and a bucket
/// written by the TypeScript worker may carry anything, so gating on it would 404
/// every digest-addressed pull against a pre-existing bucket forever. The size,
/// length, digest and schema checks below are what make the bytes safe to serve.
async fn digest_manifest_response(
    digest: &Digest,
    blob: Blob,
    head_only: bool,
    max_bytes: u64,
) -> Result<Response, AppError> {
    let unknown = || AppError::ManifestUnknown(format!("manifest unknown: {digest}"));
    if blob.meta.size > max_bytes {
        return Err(unknown());
    }
    let advertised_size = blob.meta.size;
    let bytes = match upstream::read_bounded(Some(advertised_size), blob.data, max_bytes, |error| {
        storage_failure("blob read", error)
    })
    .await
    {
        Ok(bytes) => bytes,
        Err(error @ AppError::Internal(_)) => return Err(error),
        Err(_) => return Err(unknown()),
    };
    if bytes.len() as u64 != advertised_size
        || Digest::sha256(&bytes) != *digest
        || !valid_helm_manifest(&bytes)
    {
        return Err(unknown());
    }
    Ok(bytes_response(
        MEDIA_TYPE_MANIFEST,
        digest,
        bytes,
        head_only,
    ))
}

/// A tag pointer that is absent, mistyped, oversized or backed by corrupt bytes is a
/// cache miss to rebuild from. A storage failure is not: it is surfaced so a bucket
/// outage is visible instead of hiding behind a full upstream rebuild.
async fn cached_tag_manifest(
    store: &dyn Storage,
    scope: &TagScope<'_>,
    reference: &str,
    head_only: bool,
    max_bytes: u64,
) -> Result<Option<Response>, AppError> {
    let Some(pointer) = store
        .get_tag_pointer(scope, reference)
        .await
        .map_err(|error| storage_failure("tag pointer read", error))?
    else {
        return Ok(None);
    };
    if pointer.media_type != MEDIA_TYPE_MANIFEST || pointer.size > max_bytes {
        return Ok(None);
    }
    let Some(blob) = store
        .get_blob(&pointer.digest)
        .await
        .map_err(|error| storage_failure("blob stat", error))?
    else {
        return Ok(None);
    };
    if blob.meta.size != pointer.size {
        return Ok(None);
    }
    match digest_manifest_response(&pointer.digest, blob, head_only, max_bytes).await {
        Ok(response) => Ok(Some(response)),
        Err(AppError::ManifestUnknown(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub async fn manifest(
    state: &AppState,
    proxy_host: &str,
    chart: ClassicChart,
    reference: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    if let Some(digest) = Digest::parse(reference) {
        return match find_blob(state, &digest).await? {
            Some((blob, source)) => {
                let response = digest_manifest_response(
                    &digest,
                    blob,
                    head_only,
                    state.cfg.settings.max_chart_bytes,
                )
                .await?;
                crate::metrics::record_proxy_response(
                    ProxyKind::Manifest,
                    ProxyUpstream::Classic,
                    source,
                );
                Ok(response)
            }
            None => Err(AppError::ManifestUnknown(format!(
                "manifest unknown: {digest}"
            ))),
        };
    }

    let store = backend(state, chart.ephemeral);
    let scope = TagScope {
        proxy_host,
        full_name: &chart.full_name,
    };
    if let Some(response) = cached_tag_manifest(
        store.as_ref(),
        &scope,
        reference,
        head_only,
        state.cfg.settings.max_chart_bytes,
    )
    .await?
    {
        metrics::counter!("helmoci_manifest_cache_hits_total").increment(1);
        tracing::info!(
            source = source_label(chart.source),
            ephemeral = chart.ephemeral,
            "manifest cache hit"
        );
        crate::metrics::record_proxy_response(
            ProxyKind::Manifest,
            ProxyUpstream::Classic,
            if chart.ephemeral {
                ProxySource::EphemeralCache
            } else {
                ProxySource::PersistentCache
            },
        );
        return Ok(response);
    }

    metrics::counter!("helmoci_manifest_cache_misses_total").increment(1);
    let index = fetch_index_text(state, &chart.repo_url, chart.source).await?;
    let chart_url = helmoci_core::helm::index::resolve_chart_url(
        &index,
        index_repo(&chart.repo_url, chart.source),
        &chart.chart_name,
        reference,
    )
    .map_err(AppError::from_helm_for_manifest)?;
    tracing::info!(
        source = source_label(chart.source),
        ephemeral = chart.ephemeral,
        "manifest cache miss, fetching"
    );
    let tgz = download_chart(state, &chart_url, &chart.repo_url, chart.source).await?;

    let ctx = RewriteContext {
        proxy_host: proxy_host.to_string(),
        classic_alias_by_repo: state.cfg.classic_alias_by_repo.clone(),
    };
    let max_chart_bytes = state.cfg.settings.max_chart_bytes;
    let max_expanded_chart_bytes = state.cfg.settings.max_expanded_chart_bytes;
    let BuiltChart {
        manifest_bytes,
        manifest_digest,
        config_bytes,
        config_digest,
        layer_bytes,
        layer_digest,
        pointer,
        rewrites,
    } = tokio::task::spawn_blocking(move || {
        build_helm_oci_chart_with_limits(
            tgz,
            &ctx,
            ArchiveLimits::for_chart_bytes_with_expansion(
                max_chart_bytes,
                max_expanded_chart_bytes,
            ),
        )
    })
    .await
    .map_err(|e| AppError::Internal(format!("chart build task failed: {e}")))?
    .map_err(AppError::from_helm_for_manifest)?;
    if !rewrites.is_empty() {
        tracing::info!(count = rewrites.len(), "rewrote dependencies");
    }

    tokio::try_join!(
        store.put_blob(
            &config_digest,
            MEDIA_TYPE_HELM_CONFIG,
            Bytes::from(config_bytes)
        ),
        store.put_blob(
            &layer_digest,
            MEDIA_TYPE_HELM_CHART,
            Bytes::from(layer_bytes)
        ),
        store.put_blob(
            &manifest_digest,
            MEDIA_TYPE_MANIFEST,
            Bytes::from(manifest_bytes.clone())
        ),
    )?;
    store.put_tag_pointer(&scope, reference, &pointer).await?;

    let response = bytes_response(
        MEDIA_TYPE_MANIFEST,
        &manifest_digest,
        manifest_bytes,
        head_only,
    );
    crate::metrics::record_proxy_response(
        ProxyKind::Manifest,
        ProxyUpstream::Classic,
        ProxySource::Upstream,
    );
    Ok(response)
}

pub async fn blob(
    state: &AppState,
    digest_str: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    let Some(digest) = Digest::parse(digest_str) else {
        return Err(AppError::BlobUnknown(format!(
            "invalid digest: {digest_str}"
        )));
    };
    match find_blob(state, &digest).await? {
        Some((blob, source)) => {
            let ct = blob
                .meta
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let response = blob_response(
                &ct,
                &digest,
                blob,
                head_only,
                ProxyUpstream::Classic,
                source,
            );
            crate::metrics::record_proxy_response(ProxyKind::Blob, ProxyUpstream::Classic, source);
            Ok(response)
        }
        None => Err(AppError::BlobUnknown(format!("blob unknown: {digest}"))),
    }
}

pub async fn tags(
    state: &AppState,
    chart: ClassicChart,
    query: Option<&str>,
    head_only: bool,
) -> Result<Response, AppError> {
    let (index, source) =
        fetch_index_text_with_source(state, &chart.repo_url, chart.source).await?;
    let mut tags = helmoci_core::helm::index::list_versions(
        &index,
        index_repo(&chart.repo_url, chart.source),
        &chart.chart_name,
    )
    .map_err(AppError::from_helm_for_tags)?;

    let mut n_param = None;
    let mut last = None;
    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "n" => n_param = value.parse().ok(),
                "last" => last = Some(value.into_owned()),
                _ => {}
            }
        }
    }
    if let Some(last) = last
        && let Some(index) = tags.iter().position(|tag| tag == &last)
    {
        tags.drain(..=index);
    }

    let mut link = None;
    if let Some(n) = n_param
        && tags.len() > n
    {
        let next_last = n.checked_sub(1).and_then(|index| tags.get(index)).cloned();
        tags.truncate(n);
        if let Some(next_last) = next_last {
            let encoded: String =
                url::form_urlencoded::byte_serialize(next_last.as_bytes()).collect();
            link = Some(format!(
                "</v2/{}/tags/list?n={}&last={}>; rel=\"next\"",
                chart.full_name, n, encoded
            ));
        }
    }

    let body = serde_json::json!({ "name": chart.full_name, "tags": tags }).to_string();
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len())
        .header("Docker-Distribution-API-Version", "registry/2.0");
    if let Some(link) = link {
        builder = builder.header(header::LINK, link);
    }
    let body = if head_only {
        Body::empty()
    } else {
        Body::from(body)
    };
    let response = builder.body(body).expect("static headers are valid");
    crate::metrics::record_proxy_response(ProxyKind::Tags, ProxyUpstream::Classic, source);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{build_storage, parse_config};
    use crate::error::AppError;
    use crate::state::{
        AppState, PublicDnsResolver, SharedState, build_public_http, build_test_no_redirect_http,
        build_token_http,
    };
    use futures::StreamExt;
    use helmoci_core::helm::HelmError;
    use helmoci_core::helm::tgz::testutil::build_chart_tgz;
    use helmoci_core::oci::TagPointer;
    use helmoci_storage::{BlobMeta, EphemeralStorage, StorageOp};
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};
    use std::io::Write;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn state_from_config(config: &str) -> SharedState {
        let rc = parse_config(config).unwrap();
        let storage = build_storage(&rc.settings.storage).unwrap();
        AppState::new(rc, storage, None).unwrap()
    }

    fn state_with_max(max_chart_bytes: u64) -> SharedState {
        state_from_config(&format!(
            "storage:\n  type: memory\nmax_chart_bytes: {max_chart_bytes}\n"
        ))
    }

    fn state() -> SharedState {
        state_with_max(1024)
    }

    fn state_with_storage(storage: Arc<dyn Storage>) -> SharedState {
        let rc = parse_config("storage:\n  type: memory\nmax_chart_bytes: 1024\n").unwrap();
        AppState::new(rc, storage, None).unwrap()
    }

    /// A backend that answers "here it is" and then fails mid-read: a bucket timeout,
    /// a truncated body or a TLS reset, not a missing object.
    struct FailingReadStorage {
        pointer: Option<TagPointer>,
        size: u64,
    }

    #[async_trait::async_trait]
    impl Storage for FailingReadStorage {
        async fn get_blob(&self, _digest: &Digest) -> Result<Option<Blob>, StorageError> {
            Ok(Some(Blob {
                meta: BlobMeta {
                    size: self.size,
                    content_type: Some(MEDIA_TYPE_MANIFEST.to_string()),
                },
                data: futures::stream::once(async {
                    Err(StorageError::backend(
                        StorageOp::BlobRead,
                        std::io::Error::other("bucket read timed out"),
                    ))
                })
                .boxed(),
            }))
        }

        async fn head_blob(&self, _digest: &Digest) -> Result<Option<BlobMeta>, StorageError> {
            Ok(Some(BlobMeta {
                size: self.size,
                content_type: None,
            }))
        }

        async fn put_blob(
            &self,
            _digest: &Digest,
            _content_type: &str,
            _data: Bytes,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn get_tag_pointer(
            &self,
            _scope: &TagScope<'_>,
            _tag: &str,
        ) -> Result<Option<TagPointer>, StorageError> {
            Ok(self.pointer.clone())
        }

        async fn put_tag_pointer(
            &self,
            _scope: &TagScope<'_>,
            _tag: &str,
            _pointer: &TagPointer,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn chart(server_uri: String) -> ClassicChart {
        ClassicChart {
            repo_url: server_uri,
            chart_name: "demo".into(),
            full_name: "test/demo".into(),
            ephemeral: false,
            source: ClassicSource::ConfiguredAlias,
        }
    }

    struct StaticResolver(Vec<SocketAddr>);

    impl Resolve for StaticResolver {
        fn resolve(&self, _name: Name) -> Resolving {
            let addresses = self.0.clone();
            Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) })
        }
    }

    fn state_with_clients(http: reqwest::Client, public_http: reqwest::Client) -> SharedState {
        let rc = parse_config("storage:\n  type: memory\nmax_chart_bytes: 1024\n").unwrap();
        let storage = build_storage(&rc.settings.storage).unwrap();
        let index_cache = moka::future::Cache::builder().max_capacity(32).build();
        let token_http = build_token_http().unwrap();
        let upstream_tokens = moka::future::Cache::builder()
            .max_capacity(256)
            .time_to_live(Duration::from_secs(240))
            .build();
        let ephemeral = Arc::new(EphemeralStorage::new(1024, Duration::from_secs(60)));
        Arc::new(AppState {
            cfg: rc,
            storage,
            ephemeral,
            http,
            public_http,
            token_http,
            index_cache,
            gcp: None,
            upstream_tokens,
        })
    }

    fn state_with_public_http(public_http: reqwest::Client) -> SharedState {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        state_with_clients(http, public_http)
    }

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn classic_tracing_omits_request_and_upstream_details() {
        let server = MockServer::start().await;
        let address = server.address();
        let repo_url = format!(
            "http://REPO_USER_SENTINEL:REPO_PASSWORD_SENTINEL@{address}/repo?token=REPO_QUERY_SENTINEL"
        );
        let chart_url = format!(
            "http://CHART_USER_SENTINEL:CHART_PASSWORD_SENTINEL@{address}/demo.tgz?signature=CHART_SIGNATURE_SENTINEL"
        );
        let failing_repo_url = format!(
            "http://REPO_USER_SENTINEL:REPO_PASSWORD_SENTINEL@{address}/fail?token=REPO_QUERY_SENTINEL"
        );
        let reference = "REQUEST_TAG_SENTINEL";
        let index = format!(
            "entries:\n  demo:\n    - name: demo\n      version: {reference}\n      urls: [\"{chart_url}\"]\n"
        );
        Mock::given(method("GET"))
            .and(path("/repo/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(index))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/fail/index.yaml"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        let chart_yaml = concat!(
            "name: demo\nversion: 1.0.0\ndependencies:\n",
            "  - name: DEP_NAME_SENTINEL\n    version: 1.0.0\n",
            "    repository: https://DEP_USER_SENTINEL:DEP_PASSWORD_SENTINEL@charts.example.com/private/DEP_PATH_SENTINEL?token=DEP_QUERY_SENTINEL\n",
        );
        Mock::given(method("GET"))
            .and(path("/demo.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(build_chart_tgz(&[("demo/Chart.yaml", chart_yaml)])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let output = Arc::new(Mutex::new(Vec::new()));
        let writer_output = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(move || SharedWriter(writer_output.clone()))
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        let state = state();
        let chart = ClassicChart {
            repo_url: repo_url.clone(),
            chart_name: "demo".to_string(),
            full_name: "alias/REQUEST_NAME_SENTINEL".to_string(),
            ephemeral: false,
            source: ClassicSource::ConfiguredAlias,
        };

        manifest(
            &state,
            "PROXY_HOST_SENTINEL",
            chart.clone(),
            reference,
            false,
        )
        .await
        .unwrap();
        fetch_index_text(&state, &repo_url, ClassicSource::ConfiguredAlias)
            .await
            .unwrap();
        manifest(&state, "PROXY_HOST_SENTINEL", chart, reference, false)
            .await
            .unwrap();
        fetch_index_text(&state, &failing_repo_url, ClassicSource::ConfiguredAlias)
            .await
            .unwrap_err();

        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        for event in [
            "index cache hit",
            "index cache miss",
            "manifest cache hit",
            "manifest cache miss, fetching",
            "rewrote dependenc",
            "upstream Helm index request failed",
        ] {
            assert!(logs.contains(event), "missing event {event:?}: {logs}");
        }
        // Bounded, non-secret dimensions: a 502 storm has to be attributable.
        for dimension in [
            r#"source="configured_alias""#,
            "ephemeral=false",
            r#"kind="classic_index""#,
            "status=500",
            "WARN",
        ] {
            assert!(
                logs.contains(dimension),
                "missing dimension {dimension:?}: {logs}"
            );
        }
        for secret in [
            "REPO_USER_SENTINEL",
            "REPO_PASSWORD_SENTINEL",
            "REPO_QUERY_SENTINEL",
            "CHART_USER_SENTINEL",
            "CHART_PASSWORD_SENTINEL",
            "CHART_SIGNATURE_SENTINEL",
            "DEP_USER_SENTINEL",
            "DEP_PASSWORD_SENTINEL",
            "DEP_PATH_SENTINEL",
            "DEP_QUERY_SENTINEL",
            "DEP_NAME_SENTINEL",
            "PROXY_HOST_SENTINEL",
            "REQUEST_NAME_SENTINEL",
            "REQUEST_TAG_SENTINEL",
        ] {
            assert!(!logs.contains(secret), "logs leaked {secret:?}: {logs}");
        }
        for raw_url in [&repo_url, &chart_url] {
            assert!(
                !logs.contains(raw_url),
                "logs leaked URL {raw_url:?}: {logs}"
            );
        }
        // Operators need the failing upstream, and an aliased upstream is never named
        // to the client, so the sanitized URL is logged instead. Every URL-bearing
        // line is enumerated: only the failure warnings may carry one, and never with
        // userinfo or a query.
        let url_lines: Vec<&str> = logs.lines().filter(|line| line.contains("://")).collect();
        assert!(
            !url_lines.is_empty(),
            "expected the failure warning to log the sanitized upstream: {logs}"
        );
        // The capturing subscriber is process-global, so concurrently running tests can
        // land their own warnings here. Pin the set of events allowed to carry a URL
        // rather than a single message, and enforce the sanitization invariant on every
        // one of them — that invariant is what actually matters, and it holds no matter
        // which test emitted the line.
        for line in url_lines {
            assert!(
                [
                    "upstream Helm index request failed",
                    "upstream Helm index exceeded max_index_bytes",
                    "upstream chart download failed",
                ]
                .iter()
                .any(|allowed| line.contains(allowed)),
                "unexpected URL in logs: {line}"
            );
            assert!(
                !line.contains('@') && !line.contains('?'),
                "logged URL kept userinfo or a query: {line}"
            );
        }
        assert!(
            logs.contains(&format!("url=http://{address}/fail/index.yaml")),
            "the warning does not name the failing upstream: {logs}"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn caches_index_fetches() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("entries: {}\n"))
            .expect(1)
            .mount(&server)
            .await;

        let state = state();
        let a = fetch_index_text(&state, &server.uri(), ClassicSource::ConfiguredAlias)
            .await
            .unwrap();
        let b = fetch_index_text(&state, &server.uri(), ClassicSource::ConfiguredAlias)
            .await
            .unwrap();

        assert_eq!(*a, "entries: {}\n");
        assert_eq!(*b, "entries: {}\n");
        server.verify().await;
    }

    #[tokio::test]
    async fn missing_index_is_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = fetch_index_text(&state(), &server.uri(), ClassicSource::ConfiguredAlias)
            .await
            .unwrap_err();

        assert!(matches!(err, AppError::Upstream(_)));
    }

    #[tokio::test]
    async fn download_rejects_advertised_size_over_cap() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/advertised-big.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "2048")
                    .set_body_bytes(vec![0; 2048]),
            )
            .mount(&server)
            .await;

        let url = format!("{}/advertised-big.tgz", server.uri());
        let err = download_chart(
            &state(),
            &url,
            &server.uri(),
            ClassicSource::ConfiguredAlias,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, AppError::TooLarge(_)));
    }

    #[tokio::test]
    async fn download_rejects_streamed_size_over_cap() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/streamed-big.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("transfer-encoding", "chunked")
                    .set_body_bytes(vec![0; 2048]),
            )
            .expect(2)
            .mount(&server)
            .await;

        let url = format!("{}/streamed-big.tgz", server.uri());
        let state = state();
        let response = state.http.get(&url).send().await.unwrap();
        assert_eq!(response.content_length(), None);
        drop(response);
        let err = download_chart(&state, &url, &server.uri(), ClassicSource::ConfiguredAlias)
            .await
            .unwrap_err();

        assert!(matches!(err, AppError::TooLarge(_)));
        server.verify().await;
    }

    #[tokio::test]
    async fn downloads_small_charts() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ok.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz-bytes".to_vec()))
            .mount(&server)
            .await;

        let url = format!("{}/ok.tgz", server.uri());
        let bytes = download_chart(
            &state(),
            &url,
            &server.uri(),
            ClassicSource::ConfiguredAlias,
        )
        .await
        .unwrap();

        assert_eq!(bytes, b"tgz-bytes");
    }

    #[tokio::test]
    async fn automatic_fetch_rejects_private_dns_without_contact() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("entries: {}\n"))
            .expect(0)
            .mount(&server)
            .await;
        let address = server.address();
        let http =
            build_public_http(PublicDnsResolver::new(StaticResolver(vec![*address]))).unwrap();
        let url = format!("http://public.example:{}", address.port());

        let result =
            fetch_index_text(&state_with_public_http(http), &url, ClassicSource::HostPath).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        server.verify().await;
    }

    #[tokio::test]
    async fn automatic_fetch_does_not_follow_private_redirect() {
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/private-index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("entries: {}\n"))
            .expect(0)
            .mount(&private)
            .await;
        let public = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/private-index.yaml", private.uri())),
            )
            .mount(&public)
            .await;
        let address = public.address();
        let http = build_test_no_redirect_http(StaticResolver(vec![*address])).unwrap();
        let url = format!("http://public.example:{}", address.port());

        let result =
            fetch_index_text(&state_with_public_http(http), &url, ClassicSource::HostPath).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        private.verify().await;
    }

    #[tokio::test]
    async fn trusted_index_cache_does_not_bypass_automatic_policy() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("entries: {}\n"))
            .expect(1)
            .mount(&server)
            .await;
        let address = server.address();
        let trusted_http = reqwest::Client::builder()
            .resolve("public.example", *address)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let public_http =
            build_public_http(PublicDnsResolver::new(StaticResolver(vec![*address]))).unwrap();
        let state = state_with_clients(trusted_http, public_http);
        let url = format!("http://public.example:{}", address.port());

        fetch_index_text(&state, &url, ClassicSource::ConfiguredAlias)
            .await
            .unwrap();
        let result = fetch_index_text(&state, &url, ClassicSource::HostPath).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        server.verify().await;
    }

    #[tokio::test]
    async fn automatic_download_rejects_absolute_private_url_without_contact() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chart.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"not-contacted"))
            .expect(0)
            .mount(&server)
            .await;
        let url = format!("{}/chart.tgz", server.uri());

        let result = download_chart(&state(), &url, &url, ClassicSource::HostPath).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        server.verify().await;
    }

    #[tokio::test]
    async fn configured_redirect_to_private_origin_is_rejected_without_contact() {
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("entries: {}\n"))
            .expect(0)
            .mount(&private)
            .await;
        let configured = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/index.yaml", private.uri())),
            )
            .expect(1)
            .mount(&configured)
            .await;

        let result =
            fetch_index_text(&state(), &configured.uri(), ClassicSource::ConfiguredAlias).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        configured.verify().await;
        private.verify().await;
    }

    #[tokio::test]
    async fn configured_same_origin_private_redirect_is_allowed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repo/index.yaml"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/moved/index.yaml"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/moved/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("entries: {}\n"))
            .expect(1)
            .mount(&server)
            .await;

        let text = fetch_index_text(
            &state(),
            &format!("{}/repo", server.uri()),
            ClassicSource::ConfiguredAlias,
        )
        .await
        .unwrap();

        assert_eq!(&*text, "entries: {}\n");
        server.verify().await;
    }

    #[tokio::test]
    async fn configured_redirects_stop_after_five_hops() {
        let server = MockServer::start().await;
        for hop in 0..=5 {
            Mock::given(method("GET"))
                .and(path(format!("/hop/{hop}/index.yaml")))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("location", format!("/hop/{}/index.yaml", hop + 1)),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/hop/6/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("entries: {}\n"))
            .expect(0)
            .mount(&server)
            .await;

        let result = fetch_index_text(
            &state(),
            &format!("{}/hop/0", server.uri()),
            ClassicSource::ConfiguredAlias,
        )
        .await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        server.verify().await;
    }

    #[tokio::test]
    async fn configured_redirect_rejects_repeated_location() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(
                ResponseTemplate::new(302)
                    .append_headers([("location", "/one"), ("location", "/two")]),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result =
            fetch_index_text(&state(), &server.uri(), ClassicSource::ConfiguredAlias).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        server.verify().await;
    }

    #[tokio::test]
    async fn index_rejects_advertised_and_streamed_bodies_over_cap() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/advertised/index.yaml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "2048")
                    .set_body_bytes(vec![b'a'; 2048]),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/streamed/index.yaml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("transfer-encoding", "chunked")
                    .set_body_bytes(vec![b'a'; 2048]),
            )
            .expect(1)
            .mount(&server)
            .await;
        // The index is bounded by max_index_bytes, and an index too large to read is
        // an unusable upstream (502), not an oversized chart (413).
        let state = state_from_config(
            "storage:\n  type: memory\nmax_chart_bytes: 1024\nmax_index_bytes: 1024\n",
        );

        for path in ["advertised", "streamed"] {
            let result = fetch_index_text(
                &state,
                &format!("{}/{path}", server.uri()),
                ClassicSource::ConfiguredAlias,
            )
            .await;
            assert!(matches!(result, Err(AppError::Upstream(_))), "{path}");
        }
        server.verify().await;
    }

    /// Bitnami-scale index.yaml files run well past any sane chart cap, so reusing the
    /// chart cap for the index broke every pull and every tags/list against them.
    #[tokio::test]
    async fn index_is_not_bounded_by_the_chart_download_cap() {
        let server = MockServer::start().await;
        let padding = "#".repeat(4096);
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(format!("{padding}\nentries: {{}}\n")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let state = state_from_config(
            "storage:\n  type: memory\nmax_chart_bytes: 1024\nmax_index_bytes: 65536\n",
        );

        let text = fetch_index_text(&state, &server.uri(), ClassicSource::ConfiguredAlias)
            .await
            .unwrap();

        assert!(text.len() > 1024);
        server.verify().await;
    }

    #[tokio::test]
    async fn index_invalid_utf8_returns_a_generic_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0xff, 0xfe]))
            .mount(&server)
            .await;

        let error = fetch_index_text(&state(), &server.uri(), ClassicSource::ConfiguredAlias)
            .await
            .unwrap_err();
        let AppError::Upstream(message) = error else {
            panic!("invalid UTF-8 should be an upstream error")
        };

        assert_eq!(message, "upstream Helm index was not valid UTF-8");
    }

    /// The *configured* expansion budget governs, in both directions: the compressed
    /// download cap must not double as the expansion cap (that shrank the real limit
    /// by the compression ratio and rejected charts as small as argo-cd), and the
    /// derived 10x default must not override an explicit setting.
    #[tokio::test]
    async fn configured_archive_limit_is_used_during_chart_build() {
        let server = MockServer::start().await;
        let chart_yaml = format!("name: demo\nversion: 1.0.0\nnotes: {}\n", "a".repeat(4096));
        let tgz = build_chart_tgz(&[("demo/Chart.yaml", &chart_yaml)]);
        assert!(tgz.len() < 1024, "fixture must pass the compressed limit");
        assert!(
            chart_yaml.len() > 1024 && chart_yaml.len() < 10 * 1024,
            "fixture must fall between the compressed cap and its 10x default"
        );
        let index = format!(
            "entries:\n  demo:\n    - version: 1.0.0\n      urls: [\"{}/demo.tgz\"]\n",
            server.uri()
        );
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(index))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/demo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
            .mount(&server)
            .await;

        // Under the configured budget the chart expands past it: 413, not 502.
        let rejected = manifest(
            &state_from_config(
                "storage:\n  type: memory\nmax_chart_bytes: 1024\nmax_expanded_chart_bytes: 2048\n",
            ),
            "proxy.test",
            chart(server.uri()),
            "1.0.0",
            false,
        )
        .await;
        assert!(
            matches!(rejected, Err(AppError::TooLarge(_))),
            "{rejected:?}"
        );

        // Raising the configured budget serves the same chart, even though it is
        // still far larger than the compressed download cap.
        let served = manifest(
            &state_from_config(
                "storage:\n  type: memory\nmax_chart_bytes: 1024\nmax_expanded_chart_bytes: 65536\n",
            ),
            "proxy.test",
            chart(server.uri()),
            "1.0.0",
            false,
        )
        .await
        .unwrap();
        assert_eq!(served.status(), StatusCode::OK);
    }

    /// Every configured bound the unpacker enforces must reach 413, and everything
    /// else wrong with an archive must stay 502. Built from the real errors, so the
    /// typed `ChartTooLarge` mapping is covered end to end rather than asserted on a
    /// hand-written variant.
    #[test]
    fn archive_limit_breaches_are_too_large() {
        let ctx = RewriteContext {
            proxy_host: "proxy.test".into(),
            classic_alias_by_repo: Default::default(),
        };
        let tgz = build_chart_tgz(&[
            ("demo/Chart.yaml", "name: demo\nversion: 1.0.0\n"),
            ("demo/values.yaml", "a: 1\n"),
        ]);

        for limits in [
            // cumulative expanded bytes, per-file bytes, entry count
            ArchiveLimits::new(8, 4096, 4096),
            ArchiveLimits::new(4096, 8, 4096),
            ArchiveLimits::new(4096, 4096, 1),
        ] {
            let Err(error) = build_helm_oci_chart_with_limits(tgz.clone(), &ctx, limits) else {
                panic!("expected an archive limit breach for {limits:?}")
            };
            assert!(
                matches!(error, HelmError::ChartTooLarge(_)),
                "{limits:?}: {error:?}"
            );
            let mapped = AppError::from_helm_for_manifest(error);
            assert!(matches!(mapped, AppError::TooLarge(_)), "{mapped:?}");
        }

        // The fourth bound, on PAX/GNU extension metadata, needs a hand-built archive
        // and is covered where it is enforced, in `helm::tgz`.

        // A chart that is simply not a chart stays an unusable upstream.
        let Err(error) = build_helm_oci_chart_with_limits(
            b"not a gzip stream".to_vec(),
            &ctx,
            ArchiveLimits::for_chart_bytes(4096),
        ) else {
            panic!("expected an invalid archive")
        };
        assert!(matches!(error, HelmError::InvalidChart(_)), "{error:?}");
        assert!(matches!(
            AppError::from_helm_for_manifest(error),
            AppError::Upstream(_)
        ));
    }

    #[test]
    fn both_classic_sources_follow_validated_redirects() {
        // GitHub-release-hosted charts always answer 302, and a repository behind a
        // canonical 301/308 never reaches index.yaml without this.
        assert_eq!(
            classic_client(ClassicSource::HostPath),
            (InitialClient::Public, true)
        );
        assert_eq!(
            classic_client(ClassicSource::ConfiguredAlias),
            (InitialClient::Trusted, true)
        );
    }

    /// The chart download is a separate `upstream::send` call site from the index
    /// fetch, and it is the one a 302 from a release asset lands on.
    #[tokio::test]
    async fn chart_download_follows_a_redirect_to_another_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/releases/demo.tgz"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/objects/demo.tgz"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/objects/demo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz-bytes".to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let bytes = download_chart(
            &state(),
            &format!("{}/releases/demo.tgz", server.uri()),
            &server.uri(),
            ClassicSource::ConfiguredAlias,
        )
        .await
        .unwrap();

        assert_eq!(bytes, b"tgz-bytes");
        server.verify().await;
    }

    #[tokio::test]
    async fn digest_cached_manifest_requires_matching_bounded_valid_bytes() {
        let state = state();
        let digest = Digest::sha256(b"expected manifest bytes");
        state
            .storage
            .put_blob(&digest, MEDIA_TYPE_MANIFEST, Bytes::from_static(b"corrupt"))
            .await
            .unwrap();

        let result = manifest(
            &state,
            "proxy.test",
            ClassicChart {
                repo_url: "http://unused.invalid".into(),
                chart_name: "demo".into(),
                full_name: "test/demo".into(),
                ephemeral: false,
                source: ClassicSource::ConfiguredAlias,
            },
            digest.as_str(),
            false,
        )
        .await;

        assert!(matches!(result, Err(AppError::ManifestUnknown(_))));
    }

    /// The spec's byte-compatibility requirement is that an existing helmoci bucket
    /// keeps working. The digest path has no rebuild fallback, so gating on stored
    /// metadata the format never required 404s those pulls forever.
    #[tokio::test]
    async fn digest_manifests_are_served_with_a_foreign_stored_content_type() {
        let state = state();
        let built = build_helm_oci_chart_with_limits(
            build_chart_tgz(&[("demo/Chart.yaml", "name: demo\nversion: 1.0.0\n")]),
            &RewriteContext {
                proxy_host: "proxy.test".into(),
                classic_alias_by_repo: Default::default(),
            },
            ArchiveLimits::for_chart_bytes(1024),
        )
        .unwrap();
        state
            .storage
            .put_blob(
                &built.manifest_digest,
                "application/octet-stream",
                Bytes::from(built.manifest_bytes.clone()),
            )
            .await
            .unwrap();
        let stored = state
            .storage
            .get_blob(&built.manifest_digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.meta.content_type.as_deref(),
            Some("application/octet-stream"),
            "fixture must actually persist a foreign content type"
        );

        let response = manifest(
            &state,
            "proxy.test",
            chart("http://unused.invalid".into()),
            built.manifest_digest.as_str(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            MEDIA_TYPE_MANIFEST
        );
    }

    /// A bucket outage has to be visible. Reporting it as 404 MANIFEST_UNKNOWN tells
    /// clients the chart is permanently gone, and swallowing it into a cache miss
    /// hides the outage while amplifying load on the upstream repository.
    #[tokio::test]
    async fn storage_read_failures_are_not_reported_as_missing_manifests() {
        let digest = Digest::sha256(b"a manifest that cannot be read");
        let state = state_with_storage(Arc::new(FailingReadStorage {
            pointer: None,
            size: 16,
        }));

        let error = manifest(
            &state,
            "proxy.test",
            chart("http://unused.invalid".into()),
            digest.as_str(),
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::Internal(_)), "{error:?}");

        // The tag pointer itself is intact, so nothing here is a cache miss: an
        // upstream rebuild would have failed against the unreachable repo instead.
        let state = state_with_storage(Arc::new(FailingReadStorage {
            pointer: Some(TagPointer {
                digest,
                media_type: MEDIA_TYPE_MANIFEST.into(),
                size: 16,
            }),
            size: 16,
        }));

        let error = manifest(
            &state,
            "proxy.test",
            chart("http://unused.invalid".into()),
            "1.0.0",
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::Internal(_)), "{error:?}");
    }

    /// An alias exists to hide its upstream, so a client behind one must not learn the
    /// origin, path or port it resolves to — only the operator log may name it. Neither
    /// source may ever leak userinfo or a signed query.
    #[tokio::test]
    async fn alias_upstream_failures_hide_the_upstream_from_clients() {
        let server = MockServer::start().await;
        let address = server.address();
        Mock::given(method("GET"))
            .and(path("/missing/index.yaml"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/demo.tgz"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        let repo_url =
            format!("http://REPO_USER_S:REPO_PASSWORD_S@{address}/missing?token=REPO_QUERY_S");
        let chart_url =
            format!("http://CHART_USER_S:CHART_PASSWORD_S@{address}/demo.tgz?sig=CHART_QUERY_S");

        let AppError::Upstream(index_message) =
            fetch_index_text(&state(), &repo_url, ClassicSource::ConfiguredAlias)
                .await
                .unwrap_err()
        else {
            panic!("an index status failure is an upstream error")
        };
        let AppError::Upstream(chart_message) = download_chart(
            &state(),
            &chart_url,
            &format!("http://{address}/missing"),
            ClassicSource::ConfiguredAlias,
        )
        .await
        .unwrap_err() else {
            panic!("a chart status failure is an upstream error")
        };

        assert!(index_message.contains("404"), "{index_message}");
        assert!(chart_message.contains("500"), "{chart_message}");
        for message in [&index_message, &chart_message] {
            for secret in [
                "REPO_USER_S",
                "REPO_PASSWORD_S",
                "REPO_QUERY_S",
                "CHART_USER_S",
                "CHART_PASSWORD_S",
                "CHART_QUERY_S",
                "@",
                "?",
                // The upstream itself: an alias must not disclose where it points.
                &address.to_string(),
                "missing",
                "demo.tgz",
                "http://",
            ] {
                assert!(!message.contains(secret), "leaked {secret:?}: {message}");
            }
        }
        server.verify().await;
    }

    /// The two disclosure rules that govern every upstream message, asserted on the
    /// helpers that decide them: a host-path client wrote the host into its own pull
    /// reference, so naming it back reveals nothing; an alias must stay opaque.
    #[test]
    fn client_visible_upstreams_split_by_source() {
        let url =
            url::Url::parse("https://user:pw@charts.internal.corp:8443/team/x?sig=SECRET").unwrap();
        let safe = sanitized_url(&url);

        assert_eq!(safe, "https://charts.internal.corp:8443/team/x");
        for secret in ["user", "pw", "SECRET", "@", "?"] {
            assert!(!safe.contains(secret), "leaked {secret:?}: {safe}");
        }

        assert_eq!(
            client_visible_upstream(&safe, ClassicSource::HostPath),
            safe,
            "a host-path client already knows the host it asked for"
        );

        let hidden = client_visible_upstream(&safe, ClassicSource::ConfiguredAlias);
        for part in ["charts.internal.corp", "8443", "team/x", "https://"] {
            assert!(!hidden.contains(part), "alias leaked {part:?}: {hidden}");
        }

        // The hint tells whoever can actually fix it.
        assert!(
            upstream_hint(ClassicSource::HostPath).contains("your oci:// URL"),
            "{}",
            upstream_hint(ClassicSource::HostPath)
        );
        assert!(
            upstream_hint(ClassicSource::ConfiguredAlias).contains("operator"),
            "{}",
            upstream_hint(ClassicSource::ConfiguredAlias)
        );
    }

    #[tokio::test]
    async fn corrupt_or_mistyped_tag_pointers_are_rebuilt_as_cache_misses() {
        let server = MockServer::start().await;
        let versions = ["wrong-type", "oversized", "corrupt-digest"];
        let entries = versions
            .iter()
            .map(|version| {
                format!(
                    "    - version: {version}\n      urls: [\"{}/demo.tgz\"]\n",
                    server.uri()
                )
            })
            .collect::<String>();
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(format!("entries:\n  demo:\n{entries}")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let tgz = build_chart_tgz(&[("demo/Chart.yaml", "name: demo\nversion: 1.0.0\n")]);
        Mock::given(method("GET"))
            .and(path("/demo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
            .expect(3)
            .mount(&server)
            .await;
        let state = state();
        let scope = TagScope {
            proxy_host: "proxy.test",
            full_name: "test/demo",
        };
        let bad_bytes = Bytes::from_static(b"corrupt");
        let bad_digest = Digest::sha256(b"different bytes");
        state
            .storage
            .put_blob(&bad_digest, MEDIA_TYPE_MANIFEST, bad_bytes.clone())
            .await
            .unwrap();
        for (tag, media_type, size) in [
            ("wrong-type", MEDIA_TYPE_HELM_CONFIG, bad_bytes.len() as u64),
            ("oversized", MEDIA_TYPE_MANIFEST, 1025),
            (
                "corrupt-digest",
                MEDIA_TYPE_MANIFEST,
                bad_bytes.len() as u64,
            ),
        ] {
            state
                .storage
                .put_tag_pointer(
                    &scope,
                    tag,
                    &TagPointer {
                        digest: bad_digest.clone(),
                        media_type: media_type.into(),
                        size,
                    },
                )
                .await
                .unwrap();
        }
        let chart = ClassicChart {
            repo_url: server.uri(),
            chart_name: "demo".into(),
            full_name: "test/demo".into(),
            ephemeral: false,
            source: ClassicSource::ConfiguredAlias,
        };

        for version in versions {
            let response = manifest(&state, "proxy.test", chart.clone(), version, false)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{version}");
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn configured_cross_origin_private_chart_url_is_rejected_without_contact() {
        let chart_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/demo.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"not-contacted"))
            .expect(0)
            .mount(&chart_server)
            .await;
        let repo = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "entries:\n  demo:\n    - version: 1.0.0\n      urls: [\"{}/demo.tgz\"]\n",
                chart_server.uri()
            )))
            .expect(1)
            .mount(&repo)
            .await;
        let chart = ClassicChart {
            repo_url: repo.uri(),
            chart_name: "demo".into(),
            full_name: "test/demo".into(),
            ephemeral: false,
            source: ClassicSource::ConfiguredAlias,
        };

        let result = manifest(&state(), "proxy.test", chart, "1.0.0", false).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        chart_server.verify().await;
        repo.verify().await;
    }
}
