use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use helmoci_core::helm::HelmError;
use helmoci_storage::StorageError;

#[derive(Debug)]
pub enum AppError {
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
        }
    }

    pub fn from_helm_for_tags(e: HelmError) -> Self {
        match e {
            HelmError::NotFound(m) => AppError::NameUnknown(m),
            HelmError::InvalidIndex(m) | HelmError::InvalidChart(m) => AppError::Upstream(m),
        }
    }
}

impl From<StorageError> for AppError {
    fn from(e: StorageError) -> Self {
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
    use http_body_util::BodyExt;

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
    }
}
