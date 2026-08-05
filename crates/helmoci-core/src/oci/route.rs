use percent_encoding::percent_decode_str;

use super::Digest;

#[derive(Debug, PartialEq)]
pub enum OciRoute {
    Api,
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    Tags { name: String },
    NotFound,
}

fn is_valid_manifest_reference(reference: &str) -> bool {
    if Digest::parse(reference).is_some() {
        return true;
    }
    let mut bytes = reference.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric() || byte == b'_')
        && reference.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Parse OCI Distribution V2 paths, mirroring upstream helmoci's parseOciPath.
pub fn parse_oci_path(pathname: &str) -> OciRoute {
    let Ok(decoded) = percent_decode_str(pathname).decode_utf8() else {
        return OciRoute::NotFound;
    };
    let path = decoded.into_owned();
    let Some(rest) = path.strip_prefix("/v2") else {
        return OciRoute::NotFound;
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return OciRoute::NotFound;
    }
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return OciRoute::Api;
    }

    if let Some(idx) = rest.rfind("/manifests/") {
        let name = &rest[..idx];
        let reference = &rest[idx + "/manifests/".len()..];
        if name.is_empty() || !is_valid_manifest_reference(reference) {
            return OciRoute::NotFound;
        }
        return OciRoute::Manifest {
            name: name.into(),
            reference: reference.into(),
        };
    }

    if let Some(idx) = rest.rfind("/blobs/") {
        let name = &rest[..idx];
        let digest = &rest[idx + "/blobs/".len()..];
        if name.is_empty() || digest.is_empty() || digest.contains('/') {
            return OciRoute::NotFound;
        }
        return OciRoute::Blob {
            name: name.into(),
            digest: digest.into(),
        };
    }

    if let Some(name) = rest.strip_suffix("/tags/list") {
        let name = name.trim_end_matches('/');
        if name.is_empty() {
            return OciRoute::NotFound;
        }
        return OciRoute::Tags { name: name.into() };
    }

    OciRoute::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_root() {
        assert_eq!(parse_oci_path("/v2"), OciRoute::Api);
        assert_eq!(parse_oci_path("/v2/"), OciRoute::Api);
    }

    #[test]
    fn manifest_route() {
        assert_eq!(
            parse_oci_path("/v2/a.io/b/c/manifests/1.0.0"),
            OciRoute::Manifest {
                name: "a.io/b/c".into(),
                reference: "1.0.0".into()
            }
        );
    }

    #[test]
    fn blob_route() {
        assert_eq!(
            parse_oci_path("/v2/a.io/b/blobs/sha256:abc"),
            OciRoute::Blob {
                name: "a.io/b".into(),
                digest: "sha256:abc".into()
            }
        );
    }

    #[test]
    fn tags_route() {
        assert_eq!(
            parse_oci_path("/v2/a.io/b/c/tags/list"),
            OciRoute::Tags {
                name: "a.io/b/c".into()
            }
        );
    }

    #[test]
    fn rejects_bad_paths() {
        assert_eq!(parse_oci_path("/other"), OciRoute::NotFound);
        assert_eq!(parse_oci_path("/v2/a.io/manifests/"), OciRoute::NotFound);
        assert_eq!(parse_oci_path("/v2/manifests/1.0"), OciRoute::NotFound);
        assert_eq!(parse_oci_path("/v2/x.io/manifests/a/b"), OciRoute::NotFound);
        assert_eq!(parse_oci_path("/v2/tags/list"), OciRoute::NotFound);
    }

    #[test]
    fn rejects_non_boundary_v2_prefix() {
        assert_eq!(
            parse_oci_path("/v2evil/repo/manifests/tag"),
            OciRoute::NotFound
        );
        assert_eq!(
            parse_oci_path("/v2evil/repo/blobs/sha256:abc"),
            OciRoute::NotFound
        );
        assert_eq!(parse_oci_path("/v2evil/repo/tags/list"), OciRoute::NotFound);
    }

    #[test]
    fn decodes_percent_encoding() {
        assert_eq!(
            parse_oci_path("/v2/a.io%2Fb/manifests/1.0"),
            OciRoute::Manifest {
                name: "a.io/b".into(),
                reference: "1.0".into()
            }
        );
    }

    #[test]
    fn manifest_reference_requires_a_canonical_digest_or_safe_tag() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for reference in ["1.0.0", "chart_v2", "A-tag.1", digest] {
            assert!(matches!(
                parse_oci_path(&format!("/v2/a.io/b/manifests/{reference}")),
                OciRoute::Manifest { .. }
            ));
        }
        for reference in [
            ".",
            "..",
            "tag\\private",
            "tag?query",
            "tag#fragment",
            "tag\u{1f}control",
            &"a".repeat(129),
        ] {
            assert_eq!(
                parse_oci_path(&format!("/v2/a.io/b/manifests/{reference}")),
                OciRoute::NotFound,
                "{reference:?}"
            );
        }
        for encoded in ["tag%5Cprivate", "tag%3Fquery", "tag%23fragment"] {
            assert_eq!(
                parse_oci_path(&format!("/v2/a.io/b/manifests/{encoded}")),
                OciRoute::NotFound,
                "{encoded}"
            );
        }
    }
}
