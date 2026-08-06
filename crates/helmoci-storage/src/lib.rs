pub mod ephemeral;
pub mod objstore;

pub use ephemeral::EphemeralStorage;
pub use objstore::ObjectStoreStorage;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use helmoci_core::oci::{Digest, TagPointer};
use std::fmt;

/// The storage operation that failed.
///
/// A closed vocabulary on purpose: it is the only thing [`StorageError`] renders,
/// so a key, bucket or endpoint can never be smuggled in here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOp {
    BlobRead,
    BlobStat,
    BlobWrite,
    TagRead,
    TagWrite,
}

impl fmt::Display for StorageOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StorageOp::BlobRead => "blob read",
            StorageOp::BlobStat => "blob stat",
            StorageOp::BlobWrite => "blob write",
            StorageOp::TagRead => "tag pointer read",
            StorageOp::TagWrite => "tag pointer write",
        })
    }
}

/// A storage failure, redacted so it is safe to show a client.
///
/// The server renders `to_string()` into the `message` of an OCI error body that
/// anonymous pull clients receive, while backend errors carry the bucket
/// endpoint, account id, object key and the upstream response body. So `Display`
/// renders nothing but the operation, and the backend text reaches operators two
/// other ways: it is logged inside this crate when the error is built, and it is
/// kept as [`std::error::Error::source`].
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage backend error ({op})")]
    Backend {
        op: StorageOp,
        /// Operator-only detail. It names the endpoint, bucket and key, so it
        /// must never be formatted into a response body.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl StorageError {
    /// Logs `error` for operators and wraps it in a client-safe error.
    pub fn backend<E>(op: StorageOp, error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        tracing::warn!(operation = %op, error = %error, "storage backend error");
        Self::Backend {
            op,
            source: Box::new(error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlobMeta {
    pub size: u64,
    /// None when the backend cannot persist attributes (e.g. local fs);
    /// handlers fall back to a media type they know from context.
    pub content_type: Option<String>,
}

pub struct Blob {
    pub meta: BlobMeta,
    pub data: BoxStream<'static, Result<Bytes, StorageError>>,
}

#[derive(Debug, Clone, Copy)]
pub struct TagScope<'a> {
    pub proxy_host: &'a str,
    pub full_name: &'a str,
}

// Key layout is byte-compatible with buckets written by the TypeScript helmoci.
pub fn blob_key(digest: &Digest) -> String {
    format!("blobs/{digest}")
}

pub fn tag_key(scope: &TagScope<'_>, tag: &str) -> String {
    format!("tags/{}/{}/{}", scope.proxy_host, scope.full_name, tag)
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn get_blob(&self, digest: &Digest) -> Result<Option<Blob>, StorageError>;
    async fn head_blob(&self, digest: &Digest) -> Result<Option<BlobMeta>, StorageError>;
    /// Content-addressed: silently a no-op if the digest already exists.
    async fn put_blob(
        &self,
        digest: &Digest,
        content_type: &str,
        data: Bytes,
    ) -> Result<(), StorageError>;
    async fn get_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
    ) -> Result<Option<TagPointer>, StorageError>;
    async fn put_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
        ptr: &TagPointer,
    ) -> Result<(), StorageError>;
}
