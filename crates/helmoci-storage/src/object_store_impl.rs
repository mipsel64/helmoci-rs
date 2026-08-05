use crate::{Blob, BlobMeta, Storage, StorageError, TagScope, blob_key, tag_key};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use helmoci_core::oci::{Digest, TagPointer};
use object_store::path::Path;
use object_store::{Attribute, Attributes, ObjectStore, PutMode, PutOptions};
use std::sync::Arc;

/// One implementation for every object_store backend: R2 (S3), GCS, local fs, memory.
pub struct ObjectStoreStorage {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreStorage {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    fn path(key: &str) -> Result<Path, StorageError> {
        Path::parse(key).map_err(|e| StorageError::Backend(format!("invalid key {key}: {e}")))
    }
}

fn backend_err(e: object_store::Error) -> StorageError {
    StorageError::Backend(e.to_string())
}

#[async_trait]
impl Storage for ObjectStoreStorage {
    async fn get_blob(&self, digest: &Digest) -> Result<Option<Blob>, StorageError> {
        let path = Self::path(&blob_key(digest))?;
        match self.store.get(&path).await {
            Ok(result) => {
                let size = result.meta.size;
                let content_type = result
                    .attributes
                    .get(&Attribute::ContentType)
                    .map(|value| value.to_string());
                let data = result.into_stream().map_err(backend_err).boxed();
                Ok(Some(Blob {
                    meta: BlobMeta { size, content_type },
                    data,
                }))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(backend_err(e)),
        }
    }

    async fn head_blob(&self, digest: &Digest) -> Result<Option<BlobMeta>, StorageError> {
        let path = Self::path(&blob_key(digest))?;
        match self.store.head(&path).await {
            Ok(meta) => Ok(Some(BlobMeta {
                size: meta.size,
                content_type: None,
            })),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(backend_err(e)),
        }
    }

    async fn put_blob(
        &self,
        digest: &Digest,
        content_type: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        let path = Self::path(&blob_key(digest))?;
        let mut attributes = Attributes::new();
        attributes.insert(Attribute::ContentType, content_type.to_string().into());
        let opts = PutOptions {
            mode: PutMode::Create,
            attributes,
            ..Default::default()
        };
        match self.store.put_opts(&path, data.clone().into(), opts).await {
            Ok(_) | Err(object_store::Error::AlreadyExists { .. }) => Ok(()),
            Err(object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented) => {
                let opts = PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                };
                match self.store.put_opts(&path, data.into(), opts).await {
                    Ok(_) | Err(object_store::Error::AlreadyExists { .. }) => Ok(()),
                    Err(e) => Err(backend_err(e)),
                }
            }
            Err(e) => Err(backend_err(e)),
        }
    }

    async fn get_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
    ) -> Result<Option<TagPointer>, StorageError> {
        let path = Self::path(&tag_key(scope, tag))?;
        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(backend_err)?;
                Ok(serde_json::from_slice(&bytes).ok())
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(backend_err(e)),
        }
    }

    async fn put_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
        ptr: &TagPointer,
    ) -> Result<(), StorageError> {
        let path = Self::path(&tag_key(scope, tag))?;
        let bytes = serde_json::to_vec(ptr).map_err(|e| StorageError::Backend(e.to_string()))?;
        self.store
            .put(&path, bytes.into())
            .await
            .map_err(backend_err)?;
        Ok(())
    }
}
