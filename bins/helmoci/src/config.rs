use anyhow::{Context, bail};
use helmoci_core::resolver::{
    Alias, AliasUpstream, UpstreamAuthKind, classic_alias_rewrite_map, is_valid_alias_name,
    parse_alias_upstream,
};
use helmoci_storage::{ObjectStoreStorage, Storage};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}

fn default_max_chart_bytes() -> u64 {
    50 * 1024 * 1024
}

fn default_index_ttl() -> u64 {
    600
}

fn default_ephemeral_max_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_ephemeral_ttl() -> u64 {
    1800
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_max_chart_bytes")]
    pub max_chart_bytes: u64,
    #[serde(default = "default_index_ttl")]
    pub index_cache_ttl_secs: u64,
    #[serde(default)]
    pub ephemeral_cache: EphemeralCacheConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub aliases: HashMap<String, AliasConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EphemeralCacheConfig {
    #[serde(default = "default_ephemeral_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_ephemeral_ttl")]
    pub ttl_secs: u64,
}

impl Default for EphemeralCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_ephemeral_max_bytes(),
            ttl_secs: default_ephemeral_ttl(),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    R2,
    Gcs,
    Local,
    Memory,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub backend: BackendKind,
    pub r2: Option<R2Config>,
    pub gcs: Option<GcsConfig>,
    pub local: Option<LocalConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct R2Config {
    pub endpoint: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcsConfig {
    pub bucket: String,
    pub service_account_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    pub path: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tokens: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasConfig {
    pub upstream: String,
    #[serde(default)]
    pub store: bool,
    #[serde(default)]
    pub auth: UpstreamAuthKind,
    #[serde(default)]
    pub plain_http: bool,
}

/// Parsed + validated configuration used by the running server.
pub struct RuntimeConfig {
    pub settings: Config,
    pub aliases: HashMap<String, Alias>,
    pub classic_alias_by_repo: HashMap<String, String>,
}

pub fn interpolate_env(raw: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            bail!("unterminated ${{...}} in config")
        };
        let var = &after[..end];
        let val =
            std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?;
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub fn parse_config(raw_yaml: &str) -> anyhow::Result<RuntimeConfig> {
    let interpolated = interpolate_env(raw_yaml)?;
    let settings: Config = serde_yaml_ng::from_str(&interpolated).context("invalid config")?;
    validate(settings)
}

pub fn load_config(path: &str) -> anyhow::Result<RuntimeConfig> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("cannot read config file {path}"))?;
    parse_config(&raw)
}

fn validate(settings: Config) -> anyhow::Result<RuntimeConfig> {
    match settings.storage.backend {
        BackendKind::R2 if settings.storage.r2.is_none() => {
            bail!("storage.backend is r2 but storage.r2 is missing")
        }
        BackendKind::Gcs if settings.storage.gcs.is_none() => {
            bail!("storage.backend is gcs but storage.gcs is missing")
        }
        BackendKind::Local if settings.storage.local.is_none() => {
            bail!("storage.backend is local but storage.local is missing")
        }
        _ => {}
    }
    if settings.auth.enabled && !settings.auth.tokens.iter().any(|token| !token.is_empty()) {
        bail!("auth.enabled is true but auth.tokens has no non-empty token");
    }

    let mut aliases = HashMap::new();
    for (name, alias_cfg) in &settings.aliases {
        if !is_valid_alias_name(name) {
            bail!("invalid alias name {name:?}: alphanumeric, '-', '_' only (no dots)");
        }
        let upstream = parse_alias_upstream(&alias_cfg.upstream)
            .map_err(|error| anyhow::anyhow!("alias {name}: {error}"))?;
        if matches!(upstream, AliasUpstream::Classic { .. })
            && alias_cfg.auth == UpstreamAuthKind::Gcp
        {
            bail!("alias {name}: auth: gcp is only supported for oci:// upstreams");
        }
        aliases.insert(
            name.clone(),
            Alias {
                upstream,
                store: alias_cfg.store,
                auth: alias_cfg.auth.clone(),
                plain_http: alias_cfg.plain_http,
            },
        );
    }
    let classic_alias_by_repo = classic_alias_rewrite_map(&aliases);
    Ok(RuntimeConfig {
        settings,
        aliases,
        classic_alias_by_repo,
    })
}

pub fn build_storage(cfg: &StorageConfig) -> anyhow::Result<Arc<dyn Storage>> {
    use object_store::aws::AmazonS3Builder;
    use object_store::gcp::GoogleCloudStorageBuilder;
    use object_store::local::LocalFileSystem;
    use object_store::memory::InMemory;

    let store: Arc<dyn object_store::ObjectStore> = match cfg.backend {
        BackendKind::R2 => {
            let r2 = cfg.r2.as_ref().expect("validated");
            Arc::new(
                AmazonS3Builder::new()
                    .with_endpoint(&r2.endpoint)
                    .with_bucket_name(&r2.bucket)
                    .with_access_key_id(&r2.access_key_id)
                    .with_secret_access_key(&r2.secret_access_key)
                    .with_region("auto")
                    .build()
                    .context("building R2 (S3) client")?,
            )
        }
        BackendKind::Gcs => {
            let gcs = cfg.gcs.as_ref().expect("validated");
            let mut builder = GoogleCloudStorageBuilder::from_env().with_bucket_name(&gcs.bucket);
            if let Some(key) = &gcs.service_account_key {
                builder = builder.with_service_account_path(key);
            }
            Arc::new(builder.build().context("building GCS client")?)
        }
        BackendKind::Local => {
            let local = cfg.local.as_ref().expect("validated");
            std::fs::create_dir_all(&local.path)
                .with_context(|| format!("creating storage dir {}", local.path))?;
            Arc::new(LocalFileSystem::new_with_prefix(&local.path)?)
        }
        BackendKind::Memory => Arc::new(InMemory::new()),
    };
    Ok(Arc::new(ObjectStoreStorage::new(store)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "storage:\n  backend: memory\n";

    #[test]
    fn minimal_config_gets_defaults() {
        let rc = parse_config(MINIMAL).unwrap();
        assert_eq!(rc.settings.listen, "0.0.0.0:8080");
        assert_eq!(rc.settings.max_chart_bytes, 50 * 1024 * 1024);
        assert_eq!(rc.settings.index_cache_ttl_secs, 600);
        assert!(!rc.settings.auth.enabled);
        assert!(rc.aliases.is_empty());
    }

    #[test]
    fn interpolates_env_vars() {
        unsafe { std::env::set_var("HELMOCI_TEST_TOKEN", "s3cret") };
        let yaml = "storage:\n  backend: memory\nauth:\n  enabled: true\n  tokens: [\"${HELMOCI_TEST_TOKEN}\"]\n";
        let rc = parse_config(yaml).unwrap();
        assert_eq!(rc.settings.auth.tokens, vec!["s3cret"]);
    }

    #[test]
    fn missing_env_var_fails() {
        let yaml =
            "storage:\n  backend: memory\nauth:\n  tokens: [\"${HELMOCI_DOES_NOT_EXIST}\"]\n";
        assert!(parse_config(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_config() {
        assert!(parse_config("storage:\n  backend: memory\ntypo_field: 1\n").is_err());
        assert!(parse_config("storage:\n  backend: r2\n").is_err());
        assert!(
            parse_config(
                "storage:\n  backend: memory\naliases:\n  bad.name:\n    upstream: https://x.io\n"
            )
            .is_err()
        );
        assert!(parse_config(
            "storage:\n  backend: memory\naliases:\n  a:\n    upstream: https://x.io\n    auth: gcp\n"
        )
        .is_err());
        assert!(parse_config("storage:\n  backend: memory\nauth:\n  enabled: true\n").is_err());
    }

    #[test]
    fn builds_alias_tables() {
        let yaml = concat!(
            "storage:\n  backend: memory\n",
            "aliases:\n",
            "  argo:\n    upstream: https://argoproj.github.io/argo-helm\n    store: true\n",
            "  meteora:\n    upstream: oci://asia-docker.pkg.dev/meteora-ops/charts\n    auth: gcp\n",
        );
        let rc = parse_config(yaml).unwrap();
        assert_eq!(rc.aliases.len(), 2);
        assert!(!rc.aliases["meteora"].store);
        assert_eq!(
            rc.classic_alias_by_repo.get("argoproj.github.io/argo-helm"),
            Some(&"argo".to_string())
        );
    }
}
