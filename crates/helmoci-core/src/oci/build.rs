use super::{
    Digest, MEDIA_TYPE_HELM_CHART, MEDIA_TYPE_HELM_CONFIG, MEDIA_TYPE_MANIFEST, OciDescriptor,
    OciManifest, TagPointer,
};
use crate::helm::HelmError;
use crate::helm::chart::chart_config_from_tgz;
use crate::helm::rewrite::{Rewrite, RewriteContext, rewrite_chart_dependencies};

pub struct BuiltChart {
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest: Digest,
    pub config_bytes: Vec<u8>,
    pub config_digest: Digest,
    pub layer_bytes: Vec<u8>,
    pub layer_digest: Digest,
    pub pointer: TagPointer,
    pub rewrites: Vec<Rewrite>,
}

pub fn build_helm_oci_chart(
    chart_tgz: Vec<u8>,
    ctx: &RewriteContext,
) -> Result<BuiltChart, HelmError> {
    let rewritten = rewrite_chart_dependencies(&chart_tgz, ctx)?;
    let layer_bytes = if rewritten.modified {
        rewritten.tgz
    } else {
        chart_tgz
    };

    let config_bytes = chart_config_from_tgz(&layer_bytes)?;
    let config_digest = Digest::sha256(&config_bytes);
    let layer_digest = Digest::sha256(&layer_bytes);

    let manifest = OciManifest {
        schema_version: 2,
        media_type: MEDIA_TYPE_MANIFEST.to_string(),
        config: OciDescriptor {
            media_type: MEDIA_TYPE_HELM_CONFIG.to_string(),
            digest: config_digest.clone(),
            size: config_bytes.len() as u64,
        },
        layers: vec![OciDescriptor {
            media_type: MEDIA_TYPE_HELM_CHART.to_string(),
            digest: layer_digest.clone(),
            size: layer_bytes.len() as u64,
        }],
    };
    let manifest_bytes = serde_json::to_vec(&manifest)
        .map_err(|e| HelmError::InvalidChart(format!("failed to encode manifest: {e}")))?;
    let manifest_digest = Digest::sha256(&manifest_bytes);

    Ok(BuiltChart {
        pointer: TagPointer {
            digest: manifest_digest.clone(),
            media_type: MEDIA_TYPE_MANIFEST.to_string(),
            size: manifest_bytes.len() as u64,
        },
        manifest_bytes,
        manifest_digest,
        config_bytes,
        config_digest,
        layer_bytes,
        layer_digest,
        rewrites: rewritten.rewrites,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helm::tgz::testutil::build_chart_tgz;

    fn ctx() -> RewriteContext {
        RewriteContext {
            proxy_host: "proxy.test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn builds_consistent_artifact() {
        let tgz = build_chart_tgz(&[("demo/Chart.yaml", "name: demo\nversion: 1.0.0\n")]);
        let built = build_helm_oci_chart(tgz.clone(), &ctx()).unwrap();

        let manifest: OciManifest = serde_json::from_slice(&built.manifest_bytes).unwrap();
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.media_type, MEDIA_TYPE_MANIFEST);
        assert_eq!(manifest.config.media_type, MEDIA_TYPE_HELM_CONFIG);
        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(manifest.layers[0].media_type, MEDIA_TYPE_HELM_CHART);

        assert_eq!(built.config_digest, Digest::sha256(&built.config_bytes));
        assert_eq!(built.layer_digest, Digest::sha256(&built.layer_bytes));
        assert_eq!(built.manifest_digest, Digest::sha256(&built.manifest_bytes));
        assert_eq!(built.pointer.digest, built.manifest_digest);
        assert_eq!(built.pointer.size as usize, built.manifest_bytes.len());
        assert_eq!(built.layer_bytes, tgz);
        assert!(built.rewrites.is_empty());
    }

    #[test]
    fn rewritten_dependencies_change_the_layer() {
        let tgz = build_chart_tgz(&[(
            "demo/Chart.yaml",
            "name: demo\nversion: 1.0.0\ndependencies:\n  - name: redis\n    version: 1.0.0\n    repository: https://charts.bitnami.com/bitnami\n",
        )]);
        let built = build_helm_oci_chart(tgz.clone(), &ctx()).unwrap();
        assert_eq!(built.rewrites.len(), 1);
        assert_ne!(built.layer_digest, Digest::sha256(&tgz));
    }
}
