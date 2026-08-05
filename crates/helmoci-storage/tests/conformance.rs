use bytes::Bytes;
use futures::TryStreamExt;
use helmoci_core::oci::{Digest, MEDIA_TYPE_MANIFEST, TagPointer};
use helmoci_storage::{Blob, ObjectStoreStorage, Storage, TagScope, blob_key, tag_key};
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::{ObjectStore, PutPayload};
use std::sync::Arc;

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
