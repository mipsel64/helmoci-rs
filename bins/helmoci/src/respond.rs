use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use helmoci_core::oci::Digest;
use helmoci_storage::Blob;

fn base(content_type: &str, digest: &Digest, size: u64) -> axum::http::response::Builder {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, size)
        .header("Docker-Content-Digest", digest.as_str())
        .header(header::ETAG, format!("\"{digest}\""))
        .header("Docker-Distribution-API-Version", "registry/2.0")
}

pub fn blob_response(content_type: &str, digest: &Digest, blob: Blob, head_only: bool) -> Response {
    let builder = base(content_type, digest, blob.meta.size);
    let body = if head_only {
        Body::empty()
    } else {
        Body::from_stream(blob.data)
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
