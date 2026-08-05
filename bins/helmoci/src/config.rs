use eyre::{WrapErr, bail, eyre};
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
    pub storage: Backend,
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

#[derive(Debug, Deserialize)]
#[serde(
    tag = "type",
    content = "settings",
    rename_all = "lowercase",
    deny_unknown_fields
)]
pub enum Backend {
    R2(R2Config),
    Gcs(GcsConfig),
    Local(LocalConfig),
    Memory,
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

fn env_context(name: &str) -> Result<Option<String>, std::env::VarError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(_) => Ok(None),
    }
}

pub fn parse_config(raw_yaml: &str) -> eyre::Result<RuntimeConfig> {
    let expanded =
        shellexpand::env_with_context(raw_yaml, env_context).wrap_err("expanding configuration")?;
    let settings = config::Config::builder()
        .add_source(config::File::from_str(
            expanded.as_ref(),
            config::FileFormat::Yaml,
        ))
        .build()
        .wrap_err("building configuration")?
        .try_deserialize::<Config>()
        .wrap_err("deserializing configuration")?;
    validate(settings)
}

pub fn load_config(path: &str) -> eyre::Result<RuntimeConfig> {
    let raw =
        std::fs::read_to_string(path).wrap_err_with(|| format!("reading config file {path}"))?;
    parse_config(&raw).wrap_err_with(|| format!("loading config file {path}"))
}

fn validate(settings: Config) -> eyre::Result<RuntimeConfig> {
    if settings.auth.enabled && !settings.auth.tokens.iter().any(|token| !token.is_empty()) {
        bail!("auth.enabled is true but auth.tokens has no non-empty token");
    }

    let mut aliases = HashMap::new();
    for (name, alias_cfg) in &settings.aliases {
        if !is_valid_alias_name(name) {
            bail!("invalid alias name {name:?}: alphanumeric, '-', '_' only (no dots)");
        }
        let upstream = parse_alias_upstream(&alias_cfg.upstream)
            .map_err(|error| eyre!("alias {name}: {error}"))?;
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

pub fn build_storage(cfg: &Backend) -> eyre::Result<Arc<dyn Storage>> {
    use object_store::aws::AmazonS3Builder;
    use object_store::gcp::GoogleCloudStorageBuilder;
    use object_store::local::LocalFileSystem;
    use object_store::memory::InMemory;

    let store: Arc<dyn object_store::ObjectStore> = match cfg {
        Backend::R2(r2) => Arc::new(
            AmazonS3Builder::new()
                .with_endpoint(&r2.endpoint)
                .with_bucket_name(&r2.bucket)
                .with_access_key_id(&r2.access_key_id)
                .with_secret_access_key(&r2.secret_access_key)
                .with_region("auto")
                .build()
                .wrap_err("building R2 (S3) client")?,
        ),
        Backend::Gcs(gcs) => {
            let mut builder = GoogleCloudStorageBuilder::from_env().with_bucket_name(&gcs.bucket);
            if let Some(key) = &gcs.service_account_key {
                builder = builder.with_service_account_path(key);
            }
            Arc::new(builder.build().wrap_err("building GCS client")?)
        }
        Backend::Local(local) => {
            std::fs::create_dir_all(&local.path)
                .wrap_err_with(|| format!("creating storage dir {}", local.path))?;
            Arc::new(LocalFileSystem::new_with_prefix(&local.path)?)
        }
        Backend::Memory => Arc::new(InMemory::new()),
    };
    Ok(Arc::new(ObjectStoreStorage::new(store)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    const MINIMAL: &str = "storage:\n  type: memory\n";

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        vars: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            let vars = keys
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect();
            for key in keys {
                unsafe { std::env::remove_var(key) };
            }
            Self { vars }
        }

        fn set(&self, key: &str, value: &str) {
            unsafe { std::env::set_var(key, value) };
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.vars {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    #[test]
    fn tagged_backends_deserialize() {
        let memory = parse_config(MINIMAL).unwrap();
        assert!(matches!(memory.settings.storage, Backend::Memory));

        let local =
            parse_config("storage:\n  type: local\n  settings:\n    path: /tmp/helmoci\n").unwrap();
        let Backend::Local(local) = local.settings.storage else {
            panic!("expected local backend")
        };
        assert_eq!(local.path, "/tmp/helmoci");

        let r2 = parse_config(concat!(
            "storage:\n  type: r2\n  settings:\n",
            "    endpoint: https://r2.example\n    bucket: charts\n",
            "    access_key_id: key\n    secret_access_key: secret\n",
        ))
        .unwrap();
        assert!(matches!(r2.settings.storage, Backend::R2(_)));

        let gcs = parse_config(concat!(
            "storage:\n  type: gcs\n  settings:\n",
            "    bucket: charts\n    service_account_key: /tmp/key.json\n",
        ))
        .unwrap();
        assert!(matches!(gcs.settings.storage, Backend::Gcs(_)));
    }

    #[test]
    fn rejects_invalid_backend_shapes() {
        for yaml in [
            concat!("storage:\n  back", "end: memory\n"),
            "storage:\n  type: local\n",
            "storage:\n  type: memory\n  settings:\n    path: /tmp\n",
            "storage:\n  type: local\n  settings:\n    path: /tmp\n    typo: true\n",
        ] {
            assert!(
                parse_config(yaml).is_err(),
                "unexpectedly accepted:\n{yaml}"
            );
        }
    }

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
    fn expands_shell_references_before_deserializing() {
        let _lock = env_lock();
        let env = EnvGuard::new(&["HELMOCI_TEST_LISTEN", "HELMOCI_TEST_TOKEN"]);
        env.set("HELMOCI_TEST_LISTEN", "127.0.0.1:9090");
        env.set("HELMOCI_TEST_TOKEN", "secret-token");
        let cfg = parse_config(concat!(
            "listen: $HELMOCI_TEST_LISTEN\n",
            "storage:\n  type: memory\n",
            "auth:\n  enabled: true\n  tokens: [\"${HELMOCI_TEST_TOKEN}\"]\n",
        ))
        .unwrap();
        assert_eq!(cfg.settings.listen, "127.0.0.1:9090");
        assert_eq!(cfg.settings.auth.tokens, ["secret-token"]);
    }

    #[test]
    fn leaves_missing_shell_references_unexpanded() {
        let _lock = env_lock();
        let _env = EnvGuard::new(&["HELMOCI_TEST_MISSING"]);
        let cfg = parse_config(concat!(
            "storage:\n  type: memory\n",
            "auth:\n  tokens: [\"${HELMOCI_TEST_MISSING}\"]\n",
        ))
        .unwrap();
        assert_eq!(cfg.settings.auth.tokens, ["${HELMOCI_TEST_MISSING}"]);
    }

    #[test]
    fn load_config_reads_exact_yaml_path_with_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helmoci.yaml");
        std::fs::write(&path, "storage:\n  type: memory\n").unwrap();
        let cfg = load_config(path.to_str().unwrap()).unwrap();
        assert!(matches!(cfg.settings.storage, Backend::Memory));

        let missing = dir.path().join("missing.yaml");
        let error = match load_config(missing.to_str().unwrap()) {
            Ok(_) => panic!("expected loading a missing config file to fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("reading config file"));
        assert!(error.to_string().contains("missing.yaml"));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_config() {
        assert!(parse_config("storage:\n  type: memory\ntypo_field: 1\n").is_err());
        assert!(parse_config("storage:\n  type: r2\n").is_err());
        assert!(
            parse_config(
                "storage:\n  type: memory\naliases:\n  bad.name:\n    upstream: https://x.io\n"
            )
            .is_err()
        );
        assert!(parse_config(
            "storage:\n  type: memory\naliases:\n  a:\n    upstream: https://x.io\n    auth: gcp\n"
        )
        .is_err());
        assert!(parse_config("storage:\n  type: memory\nauth:\n  enabled: true\n").is_err());
    }

    #[test]
    fn builds_alias_tables() {
        let yaml = concat!(
            "storage:\n  type: memory\n",
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
