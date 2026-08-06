use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use helmoci_core::helm::HelmError;
use helmoci_storage::StorageError;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    NameInvalid(String),
    NameUnknown(String),
    ManifestUnknown(String),
    BlobUnknown(String),
    Upstream(String),
    TooLarge(String),
    Unauthorized,
    Unsupported(String),
    Internal(String),
}

impl AppError {
    pub fn parts(&self) -> (StatusCode, &'static str, &str) {
        match self {
            AppError::NameInvalid(m) => (StatusCode::BAD_REQUEST, "NAME_INVALID", m),
            AppError::NameUnknown(m) => (StatusCode::NOT_FOUND, "NAME_UNKNOWN", m),
            AppError::ManifestUnknown(m) => (StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", m),
            AppError::BlobUnknown(m) => (StatusCode::NOT_FOUND, "BLOB_UNKNOWN", m),
            AppError::Upstream(m) => (StatusCode::BAD_GATEWAY, "DENIED", m),
            AppError::TooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, "DENIED", m),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "authentication required",
            ),
            AppError::Unsupported(m) => (StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED", m),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "DENIED", m),
        }
    }

    pub fn from_helm_for_manifest(e: HelmError) -> Self {
        match e {
            HelmError::NotFound(m) => AppError::ManifestUnknown(m),
            HelmError::InvalidIndex(m) | HelmError::InvalidChart(m) => AppError::Upstream(m),
            HelmError::ChartTooLarge(m) => AppError::TooLarge(m),
        }
    }

    pub fn from_helm_for_tags(e: HelmError) -> Self {
        match e {
            HelmError::NotFound(m) => AppError::NameUnknown(m),
            HelmError::InvalidIndex(m) | HelmError::InvalidChart(m) => AppError::Upstream(m),
            HelmError::ChartTooLarge(m) => AppError::TooLarge(m),
        }
    }
}

/// Renders an error's `source()` chain, which is where a redacted error keeps the
/// detail that must not reach a client.
struct SourceChain<'a>(&'a (dyn std::error::Error + 'static));

impl fmt::Display for SourceChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut next = self.0.source();
        let mut written = false;
        while let Some(error) = next {
            if written {
                f.write_str(": ")?;
            }
            write!(f, "{error}")?;
            written = true;
            next = error.source();
        }
        if !written {
            f.write_str("<none>")?;
        }
        Ok(())
    }
}

impl From<StorageError> for AppError {
    /// `StorageError`'s `Display` is redacted to the operation, so the endpoint,
    /// bucket, key and upstream response body only exist in its source chain.
    /// This is the boundary where that chain is dropped, so log it first — never
    /// into the message, which becomes a response body anonymous clients read.
    fn from(e: StorageError) -> Self {
        tracing::warn!(
            error = %e,
            detail = %SourceChain(&e),
            "storage operation failed; responding with a redacted error"
        );
        AppError::Internal(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let body =
            serde_json::json!({ "errors": [{ "code": code, "message": message }] }).to_string();
        let mut resp = (status, body).into_response();
        let headers = resp.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            "Docker-Distribution-API-Version",
            HeaderValue::from_static("registry/2.0"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helmoci_storage::StorageOp;
    use http_body_util::BodyExt;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing::subscriber::NoSubscriber;

    /// The innermost backend detail: an endpoint, bucket and key.
    #[derive(Debug)]
    struct BackendDetail;

    impl fmt::Display for BackendDetail {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(
                "AccessDenied at https://STORAGE_ENDPOINT_SENTINEL/SECRET_BUCKET_SENTINEL/blobs/sha256:0",
            )
        }
    }

    impl std::error::Error for BackendDetail {}

    #[derive(Debug)]
    struct BackendRequest;

    impl fmt::Display for BackendRequest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("generic PUT request error: PUT_SENTINEL")
        }
    }

    impl std::error::Error for BackendRequest {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&BackendDetail)
        }
    }

    /// Built directly, not through `StorageError::backend`, so only this
    /// boundary's own logging can put the detail in the captured output.
    fn detailed_storage_error() -> StorageError {
        StorageError::Backend {
            op: StorageOp::BlobWrite,
            source: Box::new(BackendRequest),
        }
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
    async fn storage_errors_keep_operator_detail_out_of_the_response_body() {
        // Scoped away from any global subscriber another test installed: the
        // conversion deliberately logs the detail this test is asserting about.
        let error = tracing::subscriber::with_default(NoSubscriber::default(), || {
            AppError::from(detailed_storage_error())
        });

        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        for secret in [
            "STORAGE_ENDPOINT_SENTINEL",
            "SECRET_BUCKET_SENTINEL",
            "PUT_SENTINEL",
            "AccessDenied",
            "https://",
            "sha256:0",
        ] {
            assert!(!body.contains(secret), "leaked {secret:?}: {body}");
        }
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["errors"][0]["code"], "DENIED");
        assert_eq!(
            value["errors"][0]["message"],
            "storage backend error (blob write)"
        );
    }

    #[test]
    fn storage_errors_log_the_whole_source_chain_for_operators() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer_output = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || SharedWriter(writer_output.clone()))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let _ = AppError::from(detailed_storage_error());
        });

        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        for detail in [
            "storage backend error (blob write)",
            "PUT_SENTINEL",
            "STORAGE_ENDPOINT_SENTINEL",
            "SECRET_BUCKET_SENTINEL",
        ] {
            assert!(logs.contains(detail), "missing {detail:?}: {logs}");
        }
    }

    #[tokio::test]
    async fn renders_oci_error_body() {
        let resp = AppError::ManifestUnknown("nope".into()).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()["Docker-Distribution-API-Version"],
            "registry/2.0"
        );
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert_eq!(v["errors"][0]["message"], "nope");
    }

    #[tokio::test]
    async fn name_invalid_renders_a_400_oci_error() {
        let resp = AppError::NameInvalid("bad host".into()).into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers()["Docker-Distribution-API-Version"],
            "registry/2.0"
        );
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["errors"][0]["code"], "NAME_INVALID");
        assert_eq!(v["errors"][0]["message"], "bad host");
    }

    #[test]
    fn status_mapping() {
        assert_eq!(
            AppError::Upstream("x".into()).parts().0,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            AppError::TooLarge("x".into()).parts().0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(AppError::Unauthorized.parts().0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            AppError::Unsupported("x".into()).parts().0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn maps_helm_errors_by_context() {
        let e = HelmError::NotFound("x".into());
        assert!(matches!(
            AppError::from_helm_for_manifest(e),
            AppError::ManifestUnknown(_)
        ));
        let e = HelmError::NotFound("x".into());
        assert!(matches!(
            AppError::from_helm_for_tags(e),
            AppError::NameUnknown(_)
        ));
        let e = HelmError::InvalidIndex("y".into());
        assert!(matches!(
            AppError::from_helm_for_tags(e),
            AppError::Upstream(_)
        ));
        // An archive over a configured bound is 413, not an unusable upstream.
        for mapped in [
            AppError::from_helm_for_manifest(HelmError::ChartTooLarge("z".into())),
            AppError::from_helm_for_tags(HelmError::ChartTooLarge("z".into())),
        ] {
            assert!(matches!(mapped, AppError::TooLarge(_)), "{mapped:?}");
        }
        // A malformed archive stays an unusable upstream.
        assert!(matches!(
            AppError::from_helm_for_manifest(HelmError::InvalidChart("z".into())),
            AppError::Upstream(_)
        ));
    }
}
