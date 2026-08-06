use crate::{Blob, BlobMeta, Storage, StorageError, StorageOp, TagScope, blob_key, tag_key};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use helmoci_core::oci::{Digest, TagPointer};
use object_store::path::Path;
use object_store::{Attribute, Attributes, ObjectStore, PutMode, PutOptions};
use std::sync::Arc;

/// A tag pointer is a three-field JSON document. Anything larger under `tags/` is
/// not one, so it is rejected instead of being buffered into memory.
const MAX_TAG_POINTER_BYTES: usize = 8 * 1024;

/// One implementation for every object_store backend: S3, GCS, local fs, memory.
#[derive(Clone)]
pub struct ObjectStoreStorage {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreStorage {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    fn path(op: StorageOp, key: &str) -> Result<Path, StorageError> {
        Path::parse(key).map_err(|source| {
            StorageError::backend(
                op,
                InvalidKey {
                    key: key.to_string(),
                    source,
                },
            )
        })
    }

    /// Existence probe that never fails the caller: it only ever skips work, so a
    /// `head` outage degrades to "not stored" rather than failing a write that
    /// would have succeeded.
    async fn already_stored(&self, path: &Path) -> bool {
        match self.store.head(path).await {
            Ok(_) => true,
            Err(object_store::Error::NotFound { .. }) => false,
            Err(error) => {
                tracing::debug!(
                    key = %path,
                    error = %error,
                    "existence check failed; treating the object as absent"
                );
                false
            }
        }
    }

    async fn put_once(
        &self,
        path: &Path,
        data: &Bytes,
        attributes: Attributes,
        mode: PutMode,
    ) -> Result<(), object_store::Error> {
        let opts = PutOptions {
            mode,
            attributes,
            ..Default::default()
        };
        match self.store.put_opts(path, data.clone().into(), opts).await {
            Ok(_) => Ok(()),
            // Content-addressed: whatever is already there is these same bytes.
            Err(object_store::Error::AlreadyExists { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Writes `data`, degrading through `rungs` for backends that cannot persist
    /// the attributes we would like (local fs rejects all of them; some object
    /// stores take a content type but no user metadata).
    async fn put_rungs(
        &self,
        path: &Path,
        data: &Bytes,
        rungs: &[Attributes],
        mode: PutMode,
    ) -> Result<(), object_store::Error> {
        let (last, degradable) = rungs.split_last().expect("attribute ladder is never empty");
        for attributes in degradable {
            match self
                .put_once(path, data, attributes.clone(), mode.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) if unsupported_capability(&error) => continue,
                Err(error) => return Err(error),
            }
        }
        self.put_once(path, data, last.clone(), mode).await
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid key {key}: {source}")]
struct InvalidKey {
    key: String,
    #[source]
    source: object_store::path::Error,
}

/// object_store's explicit "this backend cannot do that" signals.
fn unsupported_capability(error: &object_store::Error) -> bool {
    matches!(
        error,
        object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented
    )
}

/// True when a failed `PutMode::Create` means the backend cannot do a conditional
/// create at all, so an unconditional write is the only portable way to store the
/// blob.
///
/// `NotSupported`/`NotImplemented` are object_store's explicit signals. `Generic`
/// is the other capability shape: an S3-compatible endpoint that does not
/// implement `If-None-Match: *` rejects the request itself with 400/501, and
/// `LocalFileSystem` on a volume without hard links reports the failed link as
/// `UnableToRenameFile`. Everything object_store models as its own variant
/// (`Precondition`, `PermissionDenied`, `Unauthenticated`, `NotFound`, ...)
/// propagates untouched, so an expired credential never downgrades a write.
fn conditional_create_unsupported(error: &object_store::Error) -> bool {
    unsupported_capability(error) || matches!(error, object_store::Error::Generic { .. })
}

fn blob_attribute_rungs(digest: &Digest, content_type: &str) -> [Attributes; 3] {
    let mut full = Attributes::new();
    full.insert(Attribute::ContentType, content_type.to_string().into());
    full.insert(
        Attribute::Metadata("docker-content-digest".into()),
        digest.to_string().into(),
    );

    let mut content_type_only = Attributes::new();
    content_type_only.insert(Attribute::ContentType, content_type.to_string().into());

    [full, content_type_only, Attributes::new()]
}

#[async_trait]
impl Storage for ObjectStoreStorage {
    async fn get_blob(&self, digest: &Digest) -> Result<Option<Blob>, StorageError> {
        let path = Self::path(StorageOp::BlobRead, &blob_key(digest))?;
        match self.store.get(&path).await {
            Ok(result) => {
                let size = result.meta.size;
                let content_type = result
                    .attributes
                    .get(&Attribute::ContentType)
                    .map(|value| value.to_string());
                let data = result
                    .into_stream()
                    .map_err(|error| StorageError::backend(StorageOp::BlobRead, error))
                    .boxed();
                Ok(Some(Blob {
                    meta: BlobMeta { size, content_type },
                    data,
                }))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(StorageError::backend(StorageOp::BlobRead, error)),
        }
    }

    async fn head_blob(&self, digest: &Digest) -> Result<Option<BlobMeta>, StorageError> {
        let path = Self::path(StorageOp::BlobStat, &blob_key(digest))?;
        match self.store.head(&path).await {
            Ok(meta) => Ok(Some(BlobMeta {
                size: meta.size,
                content_type: None,
            })),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(StorageError::backend(StorageOp::BlobStat, error)),
        }
    }

    async fn put_blob(
        &self,
        digest: &Digest,
        content_type: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        let key = blob_key(digest);
        let path = Self::path(StorageOp::BlobWrite, &key)?;

        // Content-addressed: an object already at this key holds exactly these
        // bytes, so skip the upload rather than pay the egress for a 412.
        if self.already_stored(&path).await {
            return Ok(());
        }

        let rungs = blob_attribute_rungs(digest, content_type);
        match self.put_rungs(&path, &data, &rungs, PutMode::Create).await {
            Ok(()) => Ok(()),
            Err(error) if conditional_create_unsupported(&error) => {
                tracing::warn!(
                    key = %key,
                    error = %error,
                    "backend cannot create objects conditionally; retrying the write unconditionally"
                );
                // Never clobber an object we can observe. A concurrent writer can
                // only have stored these same bytes.
                if self.already_stored(&path).await {
                    return Ok(());
                }
                self.put_rungs(&path, &data, &rungs, PutMode::Overwrite)
                    .await
                    .map_err(|error| StorageError::backend(StorageOp::BlobWrite, error))
            }
            Err(error) => Err(StorageError::backend(StorageOp::BlobWrite, error)),
        }
    }

    async fn get_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
    ) -> Result<Option<TagPointer>, StorageError> {
        let key = tag_key(scope, tag);
        let path = Self::path(StorageOp::TagRead, &key)?;
        match self.store.get(&path).await {
            Ok(result) => {
                if result.meta.size > MAX_TAG_POINTER_BYTES as u64 {
                    tracing::warn!(
                        key = %key,
                        size = result.meta.size,
                        limit = MAX_TAG_POINTER_BYTES,
                        "object under tags/ is too large to be a tag pointer; treating it as a cache miss"
                    );
                    return Ok(None);
                }

                let mut stream = result.into_stream();
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk =
                        chunk.map_err(|error| StorageError::backend(StorageOp::TagRead, error))?;
                    if bytes.len() + chunk.len() > MAX_TAG_POINTER_BYTES {
                        tracing::warn!(
                            key = %key,
                            limit = MAX_TAG_POINTER_BYTES,
                            "tag pointer exceeded its size bound mid-stream; treating it as a cache miss"
                        );
                        return Ok(None);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                // An unreadable pointer behaves like a cache miss, matching upstream.
                Ok(serde_json::from_slice(&bytes).ok())
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(StorageError::backend(StorageOp::TagRead, error)),
        }
    }

    async fn put_tag_pointer(
        &self,
        scope: &TagScope<'_>,
        tag: &str,
        ptr: &TagPointer,
    ) -> Result<(), StorageError> {
        let path = Self::path(StorageOp::TagWrite, &tag_key(scope, tag))?;
        let bytes = serde_json::to_vec(ptr)
            .map_err(|error| StorageError::backend(StorageOp::TagWrite, error))?;
        self.store
            .put(&path, bytes.into())
            .await
            .map_err(|error| StorageError::backend(StorageOp::TagWrite, error))?;
        Ok(())
    }
}
