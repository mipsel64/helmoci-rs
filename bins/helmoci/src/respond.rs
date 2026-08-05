use crate::metrics::{self, ProxySource, ProxyUpstream};
use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use futures::TryStreamExt;
use helmoci_core::oci::Digest;
use helmoci_storage::Blob;
use std::convert::Infallible;

fn base(content_type: &str, digest: &Digest, size: u64) -> axum::http::response::Builder {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, size)
        .header("Docker-Content-Digest", digest.as_str())
        .header(header::ETAG, format!("\"{digest}\""))
        .header("Docker-Distribution-API-Version", "registry/2.0")
}

pub(crate) fn blob_response(
    content_type: &str,
    digest: &Digest,
    blob: Blob,
    head_only: bool,
    upstream: ProxyUpstream,
    source: ProxySource,
) -> Response {
    let builder = base(content_type, digest, blob.meta.size);
    let body = if head_only {
        Body::empty()
    } else {
        Body::from_stream(blob.data.map_ok(move |chunk| {
            metrics::record_blob_bytes(upstream, source, chunk.len());
            chunk
        }))
    };
    builder.body(body).expect("static headers are valid")
}

pub(crate) fn blob_bytes_response(
    content_type: &str,
    digest: &Digest,
    bytes: Vec<u8>,
    head_only: bool,
    upstream: ProxyUpstream,
    source: ProxySource,
) -> Response {
    let builder = base(content_type, digest, bytes.len() as u64);
    let body = if head_only {
        Body::empty()
    } else {
        let data = futures::stream::once(async move {
            metrics::record_blob_bytes(upstream, source, bytes.len());
            Ok::<_, Infallible>(Bytes::from(bytes))
        });
        Body::from_stream(data)
    };
    builder.body(body).expect("static headers are valid")
}

pub fn bytes_response(
    content_type: &str,
    digest: &Digest,
    bytes: Vec<u8>,
    head_only: bool,
) -> Response {
    let builder = base(content_type, digest, bytes.len() as u64);
    let body = if head_only {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    builder.body(body).expect("static headers are valid")
}
