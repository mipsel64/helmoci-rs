use crate::{Blob, BlobMeta, Storage, StorageError, TagScope, blob_key, tag_key};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use futures::stream;
use helmoci_core::oci::{Digest, TagPointer};
use std::time::Duration;

#[derive(Clone)]
struct Entry {
    content_type: String,
    data: Bytes,
}

/// Size-weighted, TTL-evicted in-memory storage. Backs `store: false` classic
/// aliases; single-replica only.
pub struct EphemeralStorage {
    cache: moka::future::Cache<String, Entry>,
}

impl EphemeralStorage {
    pub fn new(max_bytes: u64, ttl: Duration) -> Self {
        let cache = moka::future::Cache::builder()
            .weigher(|_key: &String, entry: &Entry| entry.data.len().try_into().unwrap_or(u32::MAX))
            .max_capacity(max_bytes)
            .time_to_live(ttl)
            .build();
        Self { cache }
    }
}

#[async_trait]
impl Storage for EphemeralStorage {
    async fn get_blob(&self, digest: &Digest) -> Result<Option<Blob>, StorageError> {
        match self.cache.get(&blob_key(digest)).await {
            Some(entry) => {
                let meta = BlobMeta {
                    size: entry.data.len() as u64,
                    content_type: Some(entry.content_type.clone()),
                };
                let data = stream::once(async move { Ok(entry.data) }).boxed();
                Ok(Some(Blob { meta, data }))
            }
            None => Ok(None),
        }
    }

    async fn head_blob(&self, digest: &Digest) -> Result<Option<BlobMeta>, StorageError> {
        Ok(self
            .cache
            .get(&blob_key(digest))
            .await
            .map(|entry| BlobMeta {
                size: entry.data.len() as u64,
                content_type: Some(entry.content_type),
            }))
    }

    async fn put_blob(
        &self,
        digest: &Digest,
        content_type: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        let entry = Entry {
            content_type: content_type.to_string(),
            data,
        };
        self.cache.entry(blob_key(digest)).or_insert(entry).await;
        Ok(())
    }

    async fn get_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
    ) -> Result<Option<TagPointer>, StorageError> {
        Ok(self
            .cache
            .get(&tag_key(scope, tag))
            .await
            .and_then(|entry| serde_json::from_slice(&entry.data).ok()))
    }

    async fn put_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
        ptr: &TagPointer,
    ) -> Result<(), StorageError> {
        let data =
            serde_json::to_vec(ptr).map_err(|error| StorageError::Backend(error.to_string()))?;
        let entry = Entry {
            content_type: "application/json".to_string(),
            data: data.into(),
        };
        self.cache.insert(tag_key(scope, tag), entry).await;
        Ok(())
    }
}
