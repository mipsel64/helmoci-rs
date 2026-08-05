use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use helmoci_core::oci::{Digest, MEDIA_TYPE_MANIFEST, TagPointer};
use helmoci_storage::{
    Blob, EphemeralStorage, ObjectStoreStorage, Storage, TagScope, blob_key, tag_key,
};
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::{
    Attribute, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

async fn collect(blob: Blob) -> Vec<u8> {
    blob.data
        .try_fold(Vec::new(), |mut acc, chunk| async move {
            acc.extend_from_slice(&chunk);
            Ok(acc)
        })
        .await
        .unwrap()
}

async fn conformance(storage: &dyn Storage) {
    let digest = Digest::sha256(b"hello");
    assert!(storage.get_blob(&digest).await.unwrap().is_none());
    assert!(storage.head_blob(&digest).await.unwrap().is_none());

    let ct = "application/octet-stream";
    storage
        .put_blob(&digest, ct, Bytes::from_static(b"hello"))
        .await
        .unwrap();
    storage
        .put_blob(&digest, ct, Bytes::from_static(b"later"))
        .await
        .unwrap();

    let blob = storage.get_blob(&digest).await.unwrap().unwrap();
    assert_eq!(blob.meta.size, 5);
    assert_eq!(collect(blob).await, b"hello");
    assert_eq!(storage.head_blob(&digest).await.unwrap().unwrap().size, 5);

    let scope = TagScope {
        proxy_host: "proxy.test",
        full_name: "a.io/b/c",
    };
    assert!(
        storage
            .get_tag_pointer(&scope, "1.0.0")
            .await
            .unwrap()
            .is_none()
    );
    let ptr = TagPointer {
        digest: digest.clone(),
        media_type: MEDIA_TYPE_MANIFEST.to_string(),
        size: 5,
    };
    storage
        .put_tag_pointer(&scope, "1.0.0", &ptr)
        .await
        .unwrap();
    assert_eq!(
        storage.get_tag_pointer(&scope, "1.0.0").await.unwrap(),
        Some(ptr)
    );
}

#[tokio::test]
async fn memory_backend() {
    conformance(&ObjectStoreStorage::new(Arc::new(InMemory::new()))).await;
}

#[tokio::test]
async fn local_backend() {
    let dir = tempfile::tempdir().unwrap();
    let fs = LocalFileSystem::new_with_prefix(dir.path()).unwrap();
    conformance(&ObjectStoreStorage::new(Arc::new(fs))).await;
}

#[tokio::test]
async fn ephemeral_backend() {
    conformance(&EphemeralStorage::new(1024 * 1024, Duration::from_secs(60))).await;
}

#[tokio::test]
async fn ephemeral_expires_entries() {
    let storage = EphemeralStorage::new(1024, Duration::from_millis(50));
    let digest = Digest::sha256(b"x");
    storage
        .put_blob(&digest, "text/plain", Bytes::from_static(b"x"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(storage.get_blob(&digest).await.unwrap().is_none());
}

#[tokio::test]
async fn memory_backend_preserves_content_type() {
    let storage = ObjectStoreStorage::new(Arc::new(InMemory::new()));
    let digest = Digest::sha256(b"ct");
    storage
        .put_blob(&digest, "application/json", Bytes::from_static(b"ct"))
        .await
        .unwrap();
    let blob = storage.get_blob(&digest).await.unwrap().unwrap();
    assert_eq!(blob.meta.content_type.as_deref(), Some("application/json"));
}

#[tokio::test]
async fn memory_backend_persists_docker_content_digest_metadata() {
    let store = Arc::new(InMemory::new());
    let storage = ObjectStoreStorage::new(store.clone());
    let digest = Digest::sha256(b"metadata");
    storage
        .put_blob(
            &digest,
            "application/octet-stream",
            Bytes::from_static(b"metadata"),
        )
        .await
        .unwrap();

    let path = object_store::path::Path::from(blob_key(&digest));
    let stored = store.get(&path).await.unwrap();
    let key = Attribute::Metadata("docker-content-digest".into());
    assert_eq!(
        stored.attributes.get(&key).map(AsRef::as_ref),
        Some(digest.as_str())
    );
}

#[tokio::test]
async fn corrupt_tag_pointer_is_a_cache_miss() {
    let store = Arc::new(InMemory::new());
    let storage = ObjectStoreStorage::new(store.clone());
    let scope = TagScope {
        proxy_host: "proxy.test",
        full_name: "a.io/b/c",
    };
    let path = object_store::path::Path::from(tag_key(&scope, "broken"));
    store
        .put(&path, PutPayload::from_static(b"not json"))
        .await
        .unwrap();

    assert_eq!(
        storage.get_tag_pointer(&scope, "broken").await.unwrap(),
        None
    );
}

#[derive(Debug)]
struct InterleavingStore {
    inner: InMemory,
    attribute_support: AttributeSupport,
    heads: AtomicUsize,
    second_head: Notify,
    first_write: Notify,
}

#[derive(Debug, Clone, Copy)]
enum AttributeSupport {
    None,
    ContentType,
}

impl fmt::Display for InterleavingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("interleaving-store")
    }
}

#[async_trait]
impl ObjectStore for InterleavingStore {
    async fn put_opts(
        &self,
        location: &object_store::path::Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        let has_metadata = opts
            .attributes
            .iter()
            .any(|(attribute, _)| matches!(attribute, Attribute::Metadata(_)));
        let attributes_unsupported = match self.attribute_support {
            AttributeSupport::None => !opts.attributes.is_empty(),
            AttributeSupport::ContentType => has_metadata,
        };
        if attributes_unsupported {
            return Err(object_store::Error::NotImplemented);
        }

        let is_first = payload
            .as_ref()
            .iter()
            .any(|chunk| chunk.as_ref() == b"first");
        if is_first {
            let result = self.inner.put_opts(location, payload, opts).await;
            self.first_write.notify_one();
            result
        } else {
            self.first_write.notified().await;
            self.inner.put_opts(location, payload, opts).await
        }
    }

    async fn put_multipart_opts(
        &self,
        location: &object_store::path::Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &object_store::path::Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        self.inner.get_opts(location, options).await
    }

    async fn head(&self, location: &object_store::path::Path) -> object_store::Result<ObjectMeta> {
        if self.heads.fetch_add(1, Ordering::SeqCst) == 0 {
            self.second_head.notified().await;
        } else {
            self.second_head.notify_one();
        }
        self.inner.head(location).await
    }

    async fn delete(&self, location: &object_store::path::Path) -> object_store::Result<()> {
        self.inner.delete(location).await
    }

    fn list(
        &self,
        prefix: Option<&object_store::path::Path>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(
        &self,
        prefix: Option<&object_store::path::Path>,
    ) -> object_store::Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy(
        &self,
        from: &object_store::path::Path,
        to: &object_store::path::Path,
    ) -> object_store::Result<()> {
        self.inner.copy(from, to).await
    }

    async fn copy_if_not_exists(
        &self,
        from: &object_store::path::Path,
        to: &object_store::path::Path,
    ) -> object_store::Result<()> {
        self.inner.copy_if_not_exists(from, to).await
    }
}

#[tokio::test]
async fn metadata_fallback_preserves_content_type() {
    let storage = ObjectStoreStorage::new(Arc::new(InterleavingStore {
        inner: InMemory::new(),
        attribute_support: AttributeSupport::ContentType,
        heads: AtomicUsize::new(0),
        second_head: Notify::new(),
        first_write: Notify::new(),
    }));
    let digest = Digest::sha256(b"first");

    storage
        .put_blob(
            &digest,
            "application/octet-stream",
            Bytes::from_static(b"first"),
        )
        .await
        .unwrap();

    let blob = storage.get_blob(&digest).await.unwrap().unwrap();
    assert_eq!(
        blob.meta.content_type.as_deref(),
        Some("application/octet-stream")
    );
}

#[tokio::test]
async fn concurrent_creates_do_not_overwrite_the_first_blob() {
    let storage = Arc::new(ObjectStoreStorage::new(Arc::new(InterleavingStore {
        inner: InMemory::new(),
        attribute_support: AttributeSupport::None,
        heads: AtomicUsize::new(0),
        second_head: Notify::new(),
        first_write: Notify::new(),
    })));
    let digest = Digest::sha256(b"first");

    let (first, second) = tokio::join!(
        storage.put_blob(
            &digest,
            "application/octet-stream",
            Bytes::from_static(b"first")
        ),
        storage.put_blob(
            &digest,
            "application/octet-stream",
            Bytes::from_static(b"second")
        ),
    );
    first.unwrap();
    second.unwrap();

    let blob = storage.get_blob(&digest).await.unwrap().unwrap();
    assert_eq!(collect(blob).await, b"first");
}

#[test]
fn keys_match_the_typescript_bucket_layout() {
    let digest = Digest::sha256(b"hello");
    let scope = TagScope {
        proxy_host: "proxy.test",
        full_name: "a.io/b/c",
    };

    assert_eq!(
        blob_key(&digest),
        "blobs/sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(tag_key(&scope, "1.0.0"), "tags/proxy.test/a.io/b/c/1.0.0");
}
