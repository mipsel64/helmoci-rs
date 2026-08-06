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
    PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult,
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
    /// When set, no `head` returns until both writers have issued theirs, so the
    /// existence pre-check cannot be what serialises two concurrent writes.
    head_gate: Option<HeadGate>,
    first_write: Notify,
}

#[derive(Debug, Default)]
struct HeadGate {
    heads: AtomicUsize,
    second_head: Notify,
}

impl InterleavingStore {
    fn new(attribute_support: AttributeSupport) -> Self {
        Self {
            inner: InMemory::new(),
            attribute_support,
            head_gate: None,
            first_write: Notify::new(),
        }
    }

    fn with_head_gate(attribute_support: AttributeSupport) -> Self {
        Self {
            head_gate: Some(HeadGate::default()),
            ..Self::new(attribute_support)
        }
    }
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
        if let Some(gate) = &self.head_gate {
            if gate.heads.fetch_add(1, Ordering::SeqCst) == 0 {
                gate.second_head.notified().await;
            } else {
                gate.second_head.notify_one();
            }
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
    let storage = ObjectStoreStorage::new(Arc::new(InterleavingStore::new(
        AttributeSupport::ContentType,
    )));
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
    let storage = Arc::new(ObjectStoreStorage::new(Arc::new(
        InterleavingStore::with_head_gate(AttributeSupport::None),
    )));
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

const SENTINEL_ENDPOINT: &str = "https://acct-8f31c0a2.r2.cloudflarestorage.com";
const SENTINEL_BUCKET: &str = "helmoci-private-cache";
const SENTINEL_BODY: &str = "InvalidAccessKeyId: the access key id you provided expired";

/// Stands in for object_store's `RetryError`, whose `Display` embeds the request
/// URI and the upstream response body.
#[derive(Debug)]
struct LeakyDetail(String);

impl fmt::Display for LeakyDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LeakyDetail {}

fn leaky_error(method: &str, location: &object_store::path::Path) -> object_store::Error {
    object_store::Error::Generic {
        store: "FaultyStore",
        source: Box::new(LeakyDetail(format!(
            "Error performing {method} {SENTINEL_ENDPOINT}/{SENTINEL_BUCKET}/{location} \
             in 1.2s, after 3 retries - Server returned error response: {SENTINEL_BODY}"
        ))),
    }
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    /// Nothing fails; the store only counts writes by mode.
    None,
    /// Every operation fails with an error naming the endpoint, bucket and key.
    Leaky,
    /// Conditional creates are rejected outright: an S3-compatible endpoint that
    /// does not implement `If-None-Match: *` answers 400/501 and a
    /// `LocalFileSystem` on a volume without hard links fails the link, both of
    /// which reach us as `Error::Generic`. Unconditional writes work.
    NoConditionalCreate,
    /// Conditional creates fail for a reason that is not a missing capability.
    ExpiredCredentials,
    /// `get` understates the object size but streams the whole body.
    LyingObjectSize,
}

#[derive(Debug)]
struct FaultyStore {
    inner: InMemory,
    failure: Failure,
    creates: AtomicUsize,
    overwrites: AtomicUsize,
}

impl FaultyStore {
    fn new(failure: Failure) -> Self {
        Self {
            inner: InMemory::new(),
            failure,
            creates: AtomicUsize::new(0),
            overwrites: AtomicUsize::new(0),
        }
    }

    fn creates(&self) -> usize {
        self.creates.load(Ordering::SeqCst)
    }

    fn overwrites(&self) -> usize {
        self.overwrites.load(Ordering::SeqCst)
    }
}

impl fmt::Display for FaultyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("faulty-store")
    }
}

#[async_trait]
impl ObjectStore for FaultyStore {
    async fn put_opts(
        &self,
        location: &object_store::path::Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        let conditional = matches!(opts.mode, PutMode::Create);
        if conditional {
            self.creates.fetch_add(1, Ordering::SeqCst);
        } else {
            self.overwrites.fetch_add(1, Ordering::SeqCst);
        }
        match (self.failure, conditional) {
            (Failure::Leaky, _) => Err(leaky_error("PUT", location)),
            (Failure::NoConditionalCreate, true) => Err(object_store::Error::Generic {
                store: "FaultyStore",
                source: "this endpoint does not implement conditional writes".into(),
            }),
            (Failure::ExpiredCredentials, true) => Err(object_store::Error::PermissionDenied {
                path: location.to_string(),
                source: "credentials expired".into(),
            }),
            _ => self.inner.put_opts(location, payload, opts).await,
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
        match self.failure {
            Failure::Leaky => Err(leaky_error("GET", location)),
            Failure::LyingObjectSize => {
                let mut result = self.inner.get_opts(location, options).await?;
                result.meta.size = 1;
                result.range = 0..1;
                Ok(result)
            }
            _ => self.inner.get_opts(location, options).await,
        }
    }

    async fn head(&self, location: &object_store::path::Path) -> object_store::Result<ObjectMeta> {
        match self.failure {
            Failure::Leaky => Err(leaky_error("HEAD", location)),
            _ => self.inner.head(location).await,
        }
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

fn assert_redacted(error: &helmoci_storage::StorageError, secrets: &[&str]) {
    let message = error.to_string();
    for secret in secrets {
        assert!(
            !message.contains(secret),
            "client-visible message leaked {secret:?}: {message}"
        );
    }
    assert!(
        message.len() < 64,
        "client-visible message grew long enough to be carrying detail: {message}"
    );
}

fn detail(error: &helmoci_storage::StorageError) -> String {
    std::error::Error::source(error)
        .map(ToString::to_string)
        .unwrap_or_default()
}

#[tokio::test]
async fn backend_errors_are_redacted_before_they_reach_a_client() {
    let storage = ObjectStoreStorage::new(Arc::new(FaultyStore::new(Failure::Leaky)));
    let digest = Digest::sha256(b"leak");
    let scope = TagScope {
        proxy_host: "charts.example.com",
        full_name: "argoproj.github.io/argo-helm/argo-cd",
    };
    let ptr = TagPointer {
        digest: digest.clone(),
        media_type: MEDIA_TYPE_MANIFEST.to_string(),
        size: 4,
    };

    let errors = [
        storage.get_blob(&digest).await.err().unwrap(),
        storage.head_blob(&digest).await.err().unwrap(),
        storage
            .put_blob(
                &digest,
                "application/octet-stream",
                Bytes::from_static(b"leak"),
            )
            .await
            .err()
            .unwrap(),
        storage
            .get_tag_pointer(&scope, "7.7.0")
            .await
            .err()
            .unwrap(),
        storage
            .put_tag_pointer(&scope, "7.7.0", &ptr)
            .await
            .err()
            .unwrap(),
    ];

    for error in &errors {
        assert_redacted(
            error,
            &[
                SENTINEL_ENDPOINT,
                SENTINEL_BUCKET,
                SENTINEL_BODY,
                "argo",
                "blobs/",
                "tags/",
                digest.as_str(),
            ],
        );
        let detail = detail(error);
        assert!(
            detail.contains(SENTINEL_ENDPOINT) && detail.contains(SENTINEL_BODY),
            "operators lost the backend detail: {detail}"
        );
    }
}

#[tokio::test]
async fn rejected_keys_are_redacted_before_they_reach_a_client() {
    let storage = ObjectStoreStorage::new(Arc::new(InMemory::new()));
    // A `Host: ..` request makes the key unparseable; the key carries the proxy
    // host and the chart name, so it must not come back in the response.
    let scope = TagScope {
        proxy_host: "..",
        full_name: "argoproj.github.io/argo-helm/argo-cd",
    };

    let error = storage
        .get_tag_pointer(&scope, "7.7.0")
        .await
        .err()
        .unwrap();

    assert_redacted(&error, &["..", "argo", "tags/", "7.7.0"]);
    assert!(
        detail(&error).contains("argo-cd"),
        "operators lost the rejected key: {}",
        detail(&error)
    );
}

#[tokio::test]
async fn put_blob_falls_back_to_an_unconditional_write() {
    let store = Arc::new(FaultyStore::new(Failure::NoConditionalCreate));
    let storage = ObjectStoreStorage::new(store.clone());
    let digest = Digest::sha256(b"portable");
    let ct = "application/octet-stream";

    storage
        .put_blob(&digest, ct, Bytes::from_static(b"portable"))
        .await
        .unwrap();

    let blob = storage.get_blob(&digest).await.unwrap().unwrap();
    assert_eq!(collect(blob).await, b"portable");
    assert_eq!(store.creates(), 1);
    assert_eq!(store.overwrites(), 1);

    // The fallback must not become a clobber: a second put of the same digest is
    // still a no-op, so bytes already stored survive.
    storage
        .put_blob(&digest, ct, Bytes::from_static(b"replaced"))
        .await
        .unwrap();
    assert_eq!(store.creates(), 1);
    assert_eq!(store.overwrites(), 1);
    let blob = storage.get_blob(&digest).await.unwrap().unwrap();
    assert_eq!(collect(blob).await, b"portable");
}

#[tokio::test]
async fn put_blob_does_not_downgrade_a_credential_failure_to_an_overwrite() {
    let store = Arc::new(FaultyStore::new(Failure::ExpiredCredentials));
    let storage = ObjectStoreStorage::new(store.clone());
    let digest = Digest::sha256(b"denied");

    storage
        .put_blob(
            &digest,
            "application/octet-stream",
            Bytes::from_static(b"denied"),
        )
        .await
        .unwrap_err();

    assert_eq!(store.creates(), 1);
    assert_eq!(
        store.overwrites(),
        0,
        "a non-capability failure must not downgrade the conditional write"
    );
    assert!(storage.get_blob(&digest).await.unwrap().is_none());
}

#[tokio::test]
async fn put_blob_skips_the_upload_when_the_digest_is_already_stored() {
    let store = Arc::new(FaultyStore::new(Failure::None));
    let storage = ObjectStoreStorage::new(store.clone());
    let digest = Digest::sha256(b"cached");
    let ct = "application/octet-stream";

    storage
        .put_blob(&digest, ct, Bytes::from_static(b"cached"))
        .await
        .unwrap();
    assert_eq!(store.creates(), 1);

    storage
        .put_blob(&digest, ct, Bytes::from_static(b"cached"))
        .await
        .unwrap();
    assert_eq!(
        store.creates(),
        1,
        "an already-stored digest must not be uploaded again"
    );
    assert_eq!(store.overwrites(), 0);
}

fn padded_pointer(digest: &Digest, padding: usize) -> Vec<u8> {
    format!(
        r#"{{"digest":"{digest}","mediaType":"{MEDIA_TYPE_MANIFEST}","size":5,"padding":"{}"}}"#,
        "x".repeat(padding)
    )
    .into_bytes()
}

#[tokio::test]
async fn oversized_tag_pointer_is_a_cache_miss() {
    let store = Arc::new(InMemory::new());
    let storage = ObjectStoreStorage::new(store.clone());
    let scope = TagScope {
        proxy_host: "proxy.test",
        full_name: "a.io/b/c",
    };
    let digest = Digest::sha256(b"hello");

    // Padding alone is parseable, so what follows is about size, not syntax.
    store
        .put(
            &object_store::path::Path::from(tag_key(&scope, "small")),
            padded_pointer(&digest, 16).into(),
        )
        .await
        .unwrap();
    assert!(
        storage
            .get_tag_pointer(&scope, "small")
            .await
            .unwrap()
            .is_some()
    );

    store
        .put(
            &object_store::path::Path::from(tag_key(&scope, "bloated")),
            padded_pointer(&digest, 512 * 1024).into(),
        )
        .await
        .unwrap();
    assert_eq!(
        storage.get_tag_pointer(&scope, "bloated").await.unwrap(),
        None,
        "an oversized object under tags/ must be a cache miss, not a buffered read"
    );
}

#[tokio::test]
async fn tag_pointer_reads_stay_bounded_when_the_backend_understates_the_size() {
    let store = Arc::new(FaultyStore::new(Failure::LyingObjectSize));
    let storage = ObjectStoreStorage::new(store.clone());
    let scope = TagScope {
        proxy_host: "proxy.test",
        full_name: "a.io/b/c",
    };
    let digest = Digest::sha256(b"hello");
    store
        .inner
        .put(
            &object_store::path::Path::from(tag_key(&scope, "liar")),
            padded_pointer(&digest, 512 * 1024).into(),
        )
        .await
        .unwrap();

    assert_eq!(
        storage.get_tag_pointer(&scope, "liar").await.unwrap(),
        None,
        "the read must be bounded by what was actually streamed, not by the metadata"
    );
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
