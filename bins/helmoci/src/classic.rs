use crate::error::AppError;
use crate::state::AppState;
use futures::StreamExt;
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
                "Could not reach upstream Helm repo at {index_url} ({e}). \\
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
