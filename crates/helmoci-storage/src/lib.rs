pub mod ephemeral;
pub mod object_store_impl;

pub use ephemeral::EphemeralStorage;
pub use object_store_impl::ObjectStoreStorage;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use helmoci_core::oci::{Digest, TagPointer};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage backend error: {0}")]
    Backend(String),
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
