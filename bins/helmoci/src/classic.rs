use crate::error::AppError;
use crate::respond::{blob_response, bytes_response};
use crate::state::AppState;
use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use helmoci_core::helm::rewrite::RewriteContext;
use helmoci_core::oci::build::{BuiltChart, build_helm_oci_chart};
use helmoci_core::oci::{
    Digest, MEDIA_TYPE_HELM_CHART, MEDIA_TYPE_HELM_CONFIG, MEDIA_TYPE_MANIFEST, OciManifest,
};
use helmoci_core::resolver::{ClassicChart, ClassicSource, is_public_hostname};
use helmoci_storage::{Blob, Storage, TagScope};
use std::sync::Arc;

/// index.yaml text for a repo, via the in-process TTL cache.
fn http_client<'a>(
    state: &'a AppState,
    url: &str,
    source: ClassicSource,
) -> Result<&'a reqwest::Client, AppError> {
    if source == ClassicSource::ConfiguredAlias {
        return Ok(&state.http);
    }
    let parsed = url::Url::parse(url)
        .map_err(|error| AppError::Upstream(format!("invalid automatic upstream URL: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.host_str().is_some_and(is_public_hostname)
    {
        return Err(AppError::Upstream(format!(
            "automatic upstream URL is not a public http(s) hostname: {url}"
        )));
    }
    Ok(&state.public_http)
}

pub async fn fetch_index_text(
    state: &AppState,
    repo_url: &str,
    source: ClassicSource,
) -> Result<Arc<String>, AppError> {
    let index_url = format!("{}/index.yaml", repo_url.trim_end_matches('/'));
    let cache_prefix = match source {
        ClassicSource::ConfiguredAlias => "configured",
        ClassicSource::HostPath => "host-path",
    };
    let cache_key = format!("{cache_prefix}:{index_url}");
    let http = http_client(state, &index_url, source)?;
    if let Some(text) = state.index_cache.get(&cache_key).await {
        tracing::debug!(url = %index_url, "index cache hit");
        return Ok(text);
    }

    let resp = http
        .get(&index_url)
        .header(
            reqwest::header::ACCEPT,
            "application/yaml, text/yaml, text/plain, */*",
        )
        .send()
        .await
        .map_err(|e| {
            AppError::Upstream(format!(
                "Could not reach upstream Helm repo at {index_url} ({e}). \
                 Check the host/path in your oci:// URL."
            ))
        })?;

    if !resp.status().is_success() {
        return Err(AppError::Upstream(format!(
            "No Helm repository at {repo_url} (index.yaml returned HTTP {}).",
            resp.status().as_u16()
        )));
    }

    let text = Arc::new(
        resp.text()
            .await
            .map_err(|e| AppError::Upstream(e.to_string()))?,
    );
    state.index_cache.insert(cache_key, text.clone()).await;
    Ok(text)
}

/// Download a chart tgz, enforcing max_chart_bytes while streaming.
pub async fn download_chart(
    state: &AppState,
    chart_url: &str,
    source: ClassicSource,
) -> Result<Vec<u8>, AppError> {
    let max = state.cfg.settings.max_chart_bytes;
    let resp = http_client(state, chart_url, source)?
        .get(chart_url)
        .send()
        .await
        .map_err(|e| {
            AppError::Upstream(format!("failed to download chart from {chart_url}: {e}"))
        })?;

    if !resp.status().is_success() {
        return Err(AppError::Upstream(format!(
            "failed to download chart ({}) from {chart_url}",
            resp.status().as_u16()
        )));
    }

    if let Some(len) = resp.content_length()
        && len > max
    {
        return Err(AppError::TooLarge(format!(
            "chart exceeds size limit ({len} > {max})"
        )));
    }

    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AppError::Upstream(format!("chart download failed: {e}")))?;
        if (out.len() + chunk.len()) as u64 > max {
            return Err(AppError::TooLarge(format!(
                "chart exceeds size limit (> {max})"
            )));
        }
        out.extend_from_slice(&chunk);
    }

    Ok(out)
}

fn backend(state: &AppState, ephemeral: bool) -> Arc<dyn Storage> {
    if ephemeral {
        state.ephemeral.clone()
    } else {
        state.storage.clone()
    }
}

/// Look in persistent storage first, then the ephemeral cache.
pub async fn find_blob(state: &AppState, digest: &Digest) -> Result<Option<Blob>, AppError> {
    if let Some(blob) = state.storage.get_blob(digest).await? {
        return Ok(Some(blob));
    }
    Ok(state.ephemeral.get_blob(digest).await?)
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

async fn digest_manifest_response(
    digest: &Digest,
    blob: Blob,
    head_only: bool,
) -> Result<Response, AppError> {
    match blob.meta.content_type.as_deref() {
        Some(MEDIA_TYPE_MANIFEST) => {
            Ok(blob_response(MEDIA_TYPE_MANIFEST, digest, blob, head_only))
        }
        Some(_) => Err(AppError::ManifestUnknown(format!(
            "manifest unknown: {digest}"
        ))),
        None => {
            let mut bytes = Vec::with_capacity(blob.meta.size as usize);
            let mut data = blob.data;
            while let Some(chunk) = data.next().await {
                bytes.extend_from_slice(&chunk?);
            }
            if !valid_helm_manifest(&bytes) {
                return Err(AppError::ManifestUnknown(format!(
                    "manifest unknown: {digest}"
                )));
            }
            Ok(bytes_response(
                MEDIA_TYPE_MANIFEST,
                digest,
                bytes,
                head_only,
            ))
        }
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
            Some(blob) => digest_manifest_response(&digest, blob, head_only).await,
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
    if let Some(ptr) = store.get_tag_pointer(&scope, reference).await?
        && let Some(blob) = store.get_blob(&ptr.digest).await?
    {
        tracing::info!(name = %chart.full_name, tag = reference, "manifest cache hit");
        return Ok(blob_response(&ptr.media_type, &ptr.digest, blob, head_only));
    }

    let index = fetch_index_text(state, &chart.repo_url, chart.source).await?;
    let chart_url = helmoci_core::helm::index::resolve_chart_url(
        &index,
        &chart.repo_url,
        &chart.chart_name,
        reference,
    )
    .map_err(AppError::from_helm_for_manifest)?;
    tracing::info!(url = %chart_url, repo = %chart.repo_url, "manifest cache miss, fetching");
    let tgz = download_chart(state, &chart_url, chart.source).await?;

    let ctx = RewriteContext {
        proxy_host: proxy_host.to_string(),
        classic_alias_by_repo: state.cfg.classic_alias_by_repo.clone(),
    };
    let BuiltChart {
        manifest_bytes,
        manifest_digest,
        config_bytes,
        config_digest,
        layer_bytes,
        layer_digest,
        pointer,
        rewrites,
    } = tokio::task::spawn_blocking(move || build_helm_oci_chart(tgz, &ctx))
        .await
        .map_err(|e| AppError::Internal(format!("chart build task failed: {e}")))?
        .map_err(AppError::from_helm_for_manifest)?;
    for r in &rewrites {
        tracing::info!(dep = %r.name, from = %r.from, to = %r.to, "rewrote dependency");
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

    Ok(bytes_response(
        MEDIA_TYPE_MANIFEST,
        &manifest_digest,
        manifest_bytes,
        head_only,
    ))
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
        Some(blob) => {
            let ct = blob
                .meta
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            Ok(blob_response(&ct, &digest, blob, head_only))
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
    let index = fetch_index_text(state, &chart.repo_url, chart.source).await?;
    let mut tags =
        helmoci_core::helm::index::list_versions(&index, &chart.repo_url, &chart.chart_name)
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
    Ok(builder.body(body).expect("static headers are valid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{build_storage, parse_config};
    use crate::error::AppError;
    use crate::state::{
        AppState, PublicDnsResolver, SharedState, build_public_http, build_test_no_redirect_http,
    };
    use helmoci_storage::EphemeralStorage;
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};
    use std::net::SocketAddr;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn state() -> SharedState {
        let rc = parse_config("storage:\n  type: memory\nmax_chart_bytes: 1024\n").unwrap();
        let storage = build_storage(&rc.settings.storage).unwrap();
        AppState::new(rc, storage).unwrap()
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
        let ephemeral = Arc::new(EphemeralStorage::new(1024, Duration::from_secs(60)));
        Arc::new(AppState {
            cfg: rc,
            storage,
            ephemeral,
            http,
            public_http,
            index_cache,
        })
    }

    fn state_with_public_http(public_http: reqwest::Client) -> SharedState {
        state_with_clients(reqwest::Client::new(), public_http)
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
        let err = download_chart(&state(), &url, ClassicSource::ConfiguredAlias)
            .await
            .unwrap_err();

        match err {
            AppError::TooLarge(message) => {
                assert_eq!(message, "chart exceeds size limit (2048 > 1024)")
            }
            _ => panic!("expected an oversized-chart error"),
        }
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
        let err = download_chart(&state, &url, ClassicSource::ConfiguredAlias)
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
        let bytes = download_chart(&state(), &url, ClassicSource::ConfiguredAlias)
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

        let result = download_chart(&state(), &url, ClassicSource::HostPath).await;

        assert!(matches!(result, Err(AppError::Upstream(_))));
        server.verify().await;
    }
}
