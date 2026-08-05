use crate::error::AppError;
use crate::respond::{blob_response, bytes_response};
use crate::state::AppState;
use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use helmoci_core::helm::rewrite::RewriteContext;
use helmoci_core::oci::build::{BuiltChart, build_helm_oci_chart};
use helmoci_core::oci::{
    Digest, MEDIA_TYPE_HELM_CHART, MEDIA_TYPE_HELM_CONFIG, MEDIA_TYPE_MANIFEST,
};
use helmoci_core::resolver::ClassicChart;
use helmoci_storage::{Blob, Storage, TagScope};
use std::sync::Arc;

/// index.yaml text for a repo, via the in-process TTL cache.
pub async fn fetch_index_text(state: &AppState, repo_url: &str) -> Result<Arc<String>, AppError> {
    let index_url = format!("{}/index.yaml", repo_url.trim_end_matches('/'));
    if let Some(text) = state.index_cache.get(&index_url).await {
        tracing::debug!(url = %index_url, "index cache hit");
        return Ok(text);
    }

    let resp = state
        .http
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
    state.index_cache.insert(index_url, text.clone()).await;
    Ok(text)
}

/// Download a chart tgz, enforcing max_chart_bytes while streaming.
pub async fn download_chart(state: &AppState, chart_url: &str) -> Result<Vec<u8>, AppError> {
    let max = state.cfg.settings.max_chart_bytes;
    let resp = state.http.get(chart_url).send().await.map_err(|e| {
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

pub async fn manifest(
    state: &AppState,
    proxy_host: &str,
    chart: ClassicChart,
    reference: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    if let Some(digest) = Digest::parse(reference) {
        return match find_blob(state, &digest).await? {
            // this registry only ever stores helm image manifests
            Some(blob) => Ok(blob_response(MEDIA_TYPE_MANIFEST, &digest, blob, head_only)),
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

    let index = fetch_index_text(state, &chart.repo_url).await?;
    let chart_url = helmoci_core::helm::index::resolve_chart_url(
        &index,
        &chart.repo_url,
        &chart.chart_name,
        reference,
    )
    .map_err(AppError::from_helm_for_manifest)?;
    tracing::info!(url = %chart_url, repo = %chart.repo_url, "manifest cache miss, fetching");
    let tgz = download_chart(state, &chart_url).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{build_storage, parse_config};
    use crate::error::AppError;
    use crate::state::{AppState, SharedState};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn state() -> SharedState {
        let rc = parse_config("storage:\n  backend: memory\nmax_chart_bytes: 1024\n").unwrap();
        let storage = build_storage(&rc.settings.storage).unwrap();
        AppState::new(rc, storage).unwrap()
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
        let a = fetch_index_text(&state, &server.uri()).await.unwrap();
        let b = fetch_index_text(&state, &server.uri()).await.unwrap();

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

        let err = fetch_index_text(&state(), &server.uri()).await.unwrap_err();

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
        let err = download_chart(&state(), &url).await.unwrap_err();

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
        let err = download_chart(&state, &url).await.unwrap_err();

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
        let bytes = download_chart(&state(), &url).await.unwrap();

        assert_eq!(bytes, b"tgz-bytes");
    }
}
