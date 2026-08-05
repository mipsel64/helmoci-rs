pub mod build;
pub mod digest;
pub mod route;

pub use digest::Digest;

use serde::{Deserialize, Serialize};

pub const MEDIA_TYPE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MEDIA_TYPE_HELM_CONFIG: &str = "application/vnd.cncf.helm.config.v1+json";
pub const MEDIA_TYPE_HELM_CHART: &str = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    pub schema_version: u32,
    pub media_type: String,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
}

/// Stored as JSON at `tags/<proxyHost>/<fullName>/<tag>` — field names must stay
/// camelCase for byte-compatibility with buckets written by the TypeScript helmoci.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagPointer {
    pub digest: Digest,
    pub media_type: String,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_pointer_json_matches_upstream_field_names() {
        let ptr = TagPointer {
            digest: Digest::sha256(b"m"),
            media_type: MEDIA_TYPE_MANIFEST.to_string(),
            size: 42,
        };
        let json = serde_json::to_string(&ptr).unwrap();
        assert!(json.contains("\"mediaType\""), "got: {json}");
        assert!(json.contains("\"digest\""));
        let back: TagPointer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ptr);
    }

    #[test]
    fn manifest_serializes_camel_case() {
        let m = OciManifest {
            schema_version: 2,
            media_type: MEDIA_TYPE_MANIFEST.to_string(),
            config: OciDescriptor {
                media_type: MEDIA_TYPE_HELM_CONFIG.to_string(),
                digest: Digest::sha256(b"c"),
                size: 1,
            },
            layers: vec![],
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"schemaVersion\":2"));
        assert!(json.contains("\"mediaType\""));
    }
}
