use crate::error::AppError;
use crate::metrics::{self, ProxySource, ProxyUpstream};
use axum::body::Body;
use axum::http::response::Builder;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::TryStreamExt;
use helmoci_core::oci::Digest;
use helmoci_storage::Blob;
use std::convert::Infallible;

/// `axum::http::response::Builder` defers header errors to `body()`, so a media
/// type that is not a legal header value would unwind the request task. Content
/// types here can originate from upstream metadata, so build fallibly.
fn base(content_type: &str, digest: &Digest, size: u64) -> Result<Builder, AppError> {
    let content_type = HeaderValue::from_str(content_type).map_err(|_| invalid_content_type())?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, size)
        .header("Docker-Content-Digest", digest.as_str())
        .header(header::ETAG, format!("\"{digest}\""))
        .header("Docker-Distribution-API-Version", "registry/2.0"))
}

fn invalid_content_type() -> AppError {
    AppError::Upstream("response media type was not a valid header value".into())
}

fn finish(builder: Builder, body: Body) -> Response {
    match builder.body(body) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "response headers were rejected");
            invalid_content_type().into_response()
        }
    }
}

pub(crate) fn blob_response(
    content_type: &str,
    digest: &Digest,
    blob: Blob,
    head_only: bool,
    upstream: ProxyUpstream,
    source: ProxySource,
) -> Response {
    let Ok(builder) = base(content_type, digest, blob.meta.size) else {
        return invalid_content_type().into_response();
    };
    let body = if head_only {
        Body::empty()
    } else {
        Body::from_stream(blob.data.map_ok(move |chunk| {
            metrics::record_blob_bytes(upstream, source, chunk.len());
            chunk
        }))
    };
    finish(builder, body)
}

pub(crate) fn blob_bytes_response(
    content_type: &str,
    digest: &Digest,
    bytes: Vec<u8>,
    head_only: bool,
    upstream: ProxyUpstream,
    source: ProxySource,
) -> Response {
    let Ok(builder) = base(content_type, digest, bytes.len() as u64) else {
        return invalid_content_type().into_response();
    };
    let body = if head_only {
        Body::empty()
    } else {
        let data = futures::stream::once(async move {
            metrics::record_blob_bytes(upstream, source, bytes.len());
            Ok::<_, Infallible>(Bytes::from(bytes))
        });
        Body::from_stream(data)
    };
    finish(builder, body)
}

pub fn bytes_response(
    content_type: &str,
    digest: &Digest,
    bytes: Vec<u8>,
    head_only: bool,
) -> Response {
    let Ok(builder) = base(content_type, digest, bytes.len() as u64) else {
        return invalid_content_type().into_response();
    };
    let body = if head_only {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    finish(builder, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_media_types_become_error_responses_instead_of_panics() {
        let digest = Digest::sha256(b"body");
        for content_type in [
            "application/vnd.oci.image.manifest.v1+json\u{1}",
            "application/vnd.oci.image.manifest.v1+json\u{7f}",
            "application/json\n",
        ] {
            let response = bytes_response(content_type, &digest, b"body".to_vec(), false);
            assert_eq!(
                response.status(),
                StatusCode::BAD_GATEWAY,
                "{content_type:?}"
            );
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        }
    }

    #[test]
    fn valid_media_types_still_produce_registry_headers() {
        let digest = Digest::sha256(b"body");
        let response = bytes_response("application/json", &digest, b"body".to_vec(), false);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["Docker-Content-Digest"], digest.as_str());
        assert_eq!(response.headers()[header::ETAG], format!("\"{digest}\""));
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
    }
}
