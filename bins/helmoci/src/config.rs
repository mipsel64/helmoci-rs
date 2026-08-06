use eyre::{WrapErr, bail, eyre};
use helmoci_core::resolver::{
    Alias, AliasUpstream, UpstreamAuthKind, classic_alias_rewrite_map, is_valid_alias_name,
    parse_alias_upstream,
};
use helmoci_storage::{ObjectStoreStorage, Storage};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

const MAX_CACHE_TTL_SECS: u64 = 1_000 * 365 * 24 * 60 * 60;

/// Cloudflare R2 signs with this region; other endpoints can override it.
const DEFAULT_S3_REGION: &str = "auto";

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}

fn default_max_chart_bytes() -> u64 {
    50 * 1024 * 1024
}

fn default_max_expanded_chart_bytes() -> u64 {
    500 * 1024 * 1024
}

fn default_max_index_bytes() -> u64 {
    64 * 1024 * 1024
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
    /// Cap on the uncompressed size of an expanded chart archive.
    #[serde(default = "default_max_expanded_chart_bytes")]
    pub max_expanded_chart_bytes: u64,
    /// Cap on a downloaded classic `index.yaml`, independent of chart size.
    #[serde(default = "default_max_index_bytes")]
    pub max_index_bytes: u64,
    #[serde(default = "default_index_ttl")]
    pub index_cache_ttl_secs: u64,
    #[serde(default)]
    pub ephemeral_cache: EphemeralCacheConfig,
    pub storage: Backend,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Unsafe opt-in: serve aliases that authenticate upstream to anonymous clients.
    #[serde(default)]
    pub allow_public_private_upstreams: bool,
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
    S3(S3Config),
    Gcs(GcsConfig),
    Local(LocalConfig),
    Memory,
}

/// Any S3-compatible object store: AWS S3 itself, Cloudflare R2, MinIO, Ceph.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    /// Service endpoint. Omit for AWS S3, which is derived from `region`.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub bucket: String,
    /// Defaults to R2's `auto`; required when `endpoint` is omitted.
    #[serde(default)]
    pub region: Option<String>,
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

pub fn parse_config(raw_yaml: &str) -> eyre::Result<RuntimeConfig> {
    let mut missing_vars = BTreeSet::new();
    let expanded =
        shellexpand::env_with_context(raw_yaml, |name: &str| match std::env::var(name) {
            Ok(value) => Ok::<_, std::env::VarError>(Some(value)),
            Err(_) => {
                missing_vars.insert(name.to_string());
                Ok(None)
            }
        })
        .wrap_err("expanding configuration")?;
    let settings = config::Config::builder()
        .add_source(config::File::from_str(
            expanded.as_ref(),
            config::FileFormat::Yaml,
        ))
        .build()
        .wrap_err("building configuration")?
        .try_deserialize::<Config>()
        .wrap_err("deserializing configuration")?;
    validate(settings, &missing_vars)
}

pub fn load_config(path: &str) -> eyre::Result<RuntimeConfig> {
    let raw =
        std::fs::read_to_string(path).wrap_err_with(|| format!("reading config file {path}"))?;
    parse_config(&raw).wrap_err_with(|| format!("loading config file {path}"))
}

/// True when `value` still carries a `${var}` or `$var` reference shellexpand left in place.
fn references_missing_var(value: &str, var: &str) -> bool {
    if value.contains(&format!("${{{var}}}")) {
        return true;
    }
    let bare = format!("${var}");
    value.match_indices(&bare).any(|(index, _)| {
        value[index + bare.len()..]
            .chars()
            .next()
            .is_none_or(|next| !(next.is_alphanumeric() || next == '_'))
    })
}

/// Secrets must never fall back to their literal `${VAR}` text.
fn reject_unexpanded_secret(
    field: &str,
    value: &str,
    missing_vars: &BTreeSet<String>,
) -> eyre::Result<()> {
    for var in missing_vars {
        if references_missing_var(value, var) {
            bail!(
                "{field} still references environment variable {var}, which is not set: \
                 helmoci refuses to use the literal reference as a credential. \
                 Set {var} before starting helmoci."
            );
        }
    }
    Ok(())
}

fn validate(settings: Config, missing_vars: &BTreeSet<String>) -> eyre::Result<RuntimeConfig> {
    if settings.index_cache_ttl_secs > MAX_CACHE_TTL_SECS {
        bail!("index_cache_ttl_secs must not exceed {MAX_CACHE_TTL_SECS} seconds (1000 years)");
    }
    if settings.ephemeral_cache.ttl_secs > MAX_CACHE_TTL_SECS {
        bail!("ephemeral_cache.ttl_secs must not exceed {MAX_CACHE_TTL_SECS} seconds (1000 years)");
    }
    if settings.max_expanded_chart_bytes == 0 {
        bail!("max_expanded_chart_bytes must be greater than zero");
    }
    if settings.max_expanded_chart_bytes < settings.max_chart_bytes {
        bail!(
            "max_expanded_chart_bytes ({}) must be at least max_chart_bytes ({}): \
             charts expand to more bytes than they download as",
            settings.max_expanded_chart_bytes,
            settings.max_chart_bytes
        );
    }
    if settings.max_index_bytes == 0 {
        bail!("max_index_bytes must be greater than zero");
    }
    if settings.ephemeral_cache.max_bytes < settings.max_chart_bytes {
        bail!(
            "ephemeral_cache.max_bytes ({}) must hold at least one max_chart_bytes ({}) artifact, \
             otherwise nothing is ever retained and every pull rebuilds the chart",
            settings.ephemeral_cache.max_bytes,
            settings.max_chart_bytes
        );
    }
    if settings.auth.enabled && !settings.auth.tokens.iter().any(|token| !token.is_empty()) {
        bail!("auth.enabled is true but auth.tokens has no non-empty token");
    }
    if let Backend::S3(s3) = &settings.storage
        && s3.endpoint.is_none()
        && s3.region.is_none()
    {
        bail!(
            "storage.settings needs either region (AWS S3, whose endpoint is derived from it) \
             or endpoint (an S3-compatible service such as Cloudflare R2 or MinIO)"
        );
    }
    if !missing_vars.is_empty() {
        for (index, token) in settings.auth.tokens.iter().enumerate() {
            reject_unexpanded_secret(&format!("auth.tokens[{index}]"), token, missing_vars)?;
        }
        match &settings.storage {
            Backend::S3(s3) => {
                reject_unexpanded_secret(
                    "storage.settings.access_key_id",
                    &s3.access_key_id,
                    missing_vars,
                )?;
                reject_unexpanded_secret(
                    "storage.settings.secret_access_key",
                    &s3.secret_access_key,
                    missing_vars,
                )?;
            }
            Backend::Gcs(gcs) => {
                if let Some(key) = &gcs.service_account_key {
                    reject_unexpanded_secret(
                        "storage.settings.service_account_key",
                        key,
                        missing_vars,
                    )?;
                }
            }
            Backend::Local(_) | Backend::Memory => {}
        }
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
    if !settings.auth.enabled && !settings.allow_public_private_upstreams {
        let mut credentialed: Vec<&str> = aliases
            .iter()
            .filter(|(_, alias)| !matches!(alias.auth, UpstreamAuthKind::None))
            .map(|(name, _)| name.as_str())
            .collect();
        credentialed.sort_unstable();
        if !credentialed.is_empty() {
            bail!(
                "aliases [{}] authenticate to their upstream while auth.enabled is false: \
                 helmoci holds those upstream credentials, so it would republish private \
                 upstream content to anonymous clients. Enable auth.enabled with at least one \
                 auth.tokens entry, or set allow_public_private_upstreams: true to accept that \
                 (unsafe: only for mirroring private charts onto a trusted network).",
                credentialed.join(", ")
            );
        }
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
        Backend::S3(s3) => {
            let builder = AmazonS3Builder::new()
                .with_bucket_name(&s3.bucket)
                .with_access_key_id(&s3.access_key_id)
                .with_secret_access_key(&s3.secret_access_key)
                .with_region(s3.region.as_deref().unwrap_or(DEFAULT_S3_REGION));
            // A configured endpoint addresses buckets path-style, which is what R2 and
            // MinIO expect; AWS S3 itself is addressed virtual-hosted style.
            let builder = match &s3.endpoint {
                Some(endpoint) => builder.with_endpoint(endpoint),
                None => builder.with_virtual_hosted_style_request(true),
            };
            Arc::new(builder.build().wrap_err("building S3 client")?)
        }
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
            "storage:\n  type: s3\n  settings:\n",
            "    endpoint: https://acct.r2.cloudflarestorage.com\n    bucket: charts\n",
            "    access_key_id: key\n    secret_access_key: secret\n",
        ))
        .unwrap();
        let Backend::S3(r2) = r2.settings.storage else {
            panic!("expected s3 backend")
        };
        assert_eq!(
            r2.endpoint.as_deref(),
            Some("https://acct.r2.cloudflarestorage.com")
        );
        assert_eq!(r2.region, None);

        let gcs = parse_config(concat!(
            "storage:\n  type: gcs\n  settings:\n",
            "    bucket: charts\n    service_account_key: /tmp/key.json\n",
        ))
        .unwrap();
        assert!(matches!(gcs.settings.storage, Backend::Gcs(_)));
    }

    #[test]
    fn s3_accepts_a_region_without_an_endpoint() {
        let cfg = parse_config(concat!(
            "storage:\n  type: s3\n  settings:\n",
            "    bucket: charts\n    region: ap-southeast-1\n",
            "    access_key_id: key\n    secret_access_key: secret\n",
        ))
        .unwrap();
        let Backend::S3(s3) = cfg.settings.storage else {
            panic!("expected s3 backend")
        };
        assert_eq!(s3.endpoint, None);
        assert_eq!(s3.region.as_deref(), Some("ap-southeast-1"));
    }

    #[test]
    fn s3_rejects_omitting_both_endpoint_and_region() {
        let error = match parse_config(concat!(
            "storage:\n  type: s3\n  settings:\n",
            "    bucket: charts\n",
            "    access_key_id: key\n    secret_access_key: secret\n",
        )) {
            Ok(_) => panic!("expected an s3 backend without endpoint or region to be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();

        assert!(message.contains("region"), "{message}");
        assert!(message.contains("endpoint"), "{message}");
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
    fn accepts_moka_ttl_boundary_for_both_caches() {
        let rc = parse_config(concat!(
            "storage:\n  type: memory\n",
            "index_cache_ttl_secs: 31536000000\n",
            "ephemeral_cache:\n  ttl_secs: 31536000000\n",
        ))
        .unwrap();

        assert_eq!(rc.settings.index_cache_ttl_secs, 31_536_000_000);
        assert_eq!(rc.settings.ephemeral_cache.ttl_secs, 31_536_000_000);
    }

    #[test]
    fn rejects_index_cache_ttl_one_second_over_moka_limit() {
        let error = match parse_config(concat!(
            "storage:\n  type: memory\n",
            "index_cache_ttl_secs: 31536000001\n",
        )) {
            Ok(_) => panic!("expected oversized index cache TTL to be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();

        assert!(message.contains("index_cache_ttl_secs"), "{message}");
        assert!(message.contains("31536000000"), "{message}");
    }

    #[test]
    fn rejects_ephemeral_cache_ttl_one_second_over_moka_limit() {
        let error = match parse_config(concat!(
            "storage:\n  type: memory\n",
            "ephemeral_cache:\n  ttl_secs: 31536000001\n",
        )) {
            Ok(_) => panic!("expected oversized ephemeral cache TTL to be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();

        assert!(message.contains("ephemeral_cache.ttl_secs"), "{message}");
        assert!(message.contains("31536000000"), "{message}");
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
            "storage:\n  type: local\n  settings:\n",
            "    path: /tmp/${HELMOCI_TEST_MISSING}\n",
        ))
        .unwrap();
        let Backend::Local(local) = cfg.settings.storage else {
            panic!("expected local backend")
        };
        assert_eq!(local.path, "/tmp/${HELMOCI_TEST_MISSING}");
    }

    #[test]
    fn rejects_unexpanded_references_in_secret_fields() {
        let _lock = env_lock();
        let _env = EnvGuard::new(&["HELMOCI_TEST_MISSING"]);
        for (yaml, field) in [
            (
                concat!(
                    "storage:\n  type: memory\n",
                    "auth:\n  enabled: true\n  tokens: [\"${HELMOCI_TEST_MISSING}\"]\n",
                ),
                "auth.tokens[0]",
            ),
            (
                concat!(
                    "storage:\n  type: memory\n",
                    "auth:\n  tokens: [\"good\", \"$HELMOCI_TEST_MISSING\"]\n",
                ),
                "auth.tokens[1]",
            ),
            (
                concat!(
                    "storage:\n  type: s3\n  settings:\n",
                    "    endpoint: https://s3.example\n    bucket: charts\n",
                    "    access_key_id: ${HELMOCI_TEST_MISSING}\n    secret_access_key: secret\n",
                ),
                "storage.settings.access_key_id",
            ),
            (
                concat!(
                    "storage:\n  type: s3\n  settings:\n",
                    "    endpoint: https://s3.example\n    bucket: charts\n",
                    "    access_key_id: key\n    secret_access_key: ${HELMOCI_TEST_MISSING}\n",
                ),
                "storage.settings.secret_access_key",
            ),
            (
                concat!(
                    "storage:\n  type: gcs\n  settings:\n",
                    "    bucket: charts\n    service_account_key: ${HELMOCI_TEST_MISSING}\n",
                ),
                "storage.settings.service_account_key",
            ),
        ] {
            let error = match parse_config(yaml) {
                Ok(_) => panic!("unexpectedly accepted unexpanded secret:\n{yaml}"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(field), "{error}");
            assert!(error.contains("HELMOCI_TEST_MISSING"), "{error}");
        }
    }

    #[test]
    fn secrets_from_the_environment_may_contain_dollar_signs() {
        let _lock = env_lock();
        let env = EnvGuard::new(&["HELMOCI_TEST_TOKEN", "HELMOCI_TEST_MISSING"]);
        env.set("HELMOCI_TEST_TOKEN", "ab$Cd${Ef}");
        let cfg = parse_config(concat!(
            "storage:\n  type: memory\n",
            "auth:\n  enabled: true\n  tokens: [\"${HELMOCI_TEST_TOKEN}\"]\n",
        ))
        .unwrap();
        assert_eq!(cfg.settings.auth.tokens, ["ab$Cd${Ef}"]);
    }

    #[test]
    fn accepts_secret_values_without_environment_references() {
        let cfg = parse_config(concat!(
            "storage:\n  type: memory\n",
            "auth:\n  enabled: true\n  tokens: [\"literal-token\", \"pa$$-and-100$\"]\n",
        ))
        .unwrap();
        assert_eq!(cfg.settings.auth.tokens.len(), 2);
    }

    #[test]
    fn new_size_limits_expose_documented_defaults() {
        let rc = parse_config(MINIMAL).unwrap();
        assert_eq!(rc.settings.max_expanded_chart_bytes, 524_288_000);
        assert_eq!(rc.settings.max_index_bytes, 67_108_864);
    }

    #[test]
    fn rejects_unusable_size_limits() {
        for (yaml, field) in [
            (
                "storage:\n  type: memory\nmax_expanded_chart_bytes: 0\n",
                "max_expanded_chart_bytes",
            ),
            (
                "storage:\n  type: memory\nmax_index_bytes: 0\n",
                "max_index_bytes",
            ),
            (
                concat!(
                    "storage:\n  type: memory\n",
                    "max_chart_bytes: 1048576\nmax_expanded_chart_bytes: 1048575\n",
                ),
                "max_expanded_chart_bytes",
            ),
            (
                concat!(
                    "storage:\n  type: memory\n",
                    "max_chart_bytes: 1048576\nephemeral_cache:\n  max_bytes: 1048575\n",
                ),
                "ephemeral_cache.max_bytes",
            ),
        ] {
            let error = match parse_config(yaml) {
                Ok(_) => panic!("unexpectedly accepted:\n{yaml}"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(field), "{error}");
        }
    }

    #[test]
    fn accepts_size_limits_at_their_lower_bounds() {
        let rc = parse_config(concat!(
            "storage:\n  type: memory\n",
            "max_chart_bytes: 1048576\nmax_expanded_chart_bytes: 1048576\n",
            "max_index_bytes: 1\nephemeral_cache:\n  max_bytes: 1048576\n",
        ))
        .unwrap();
        assert_eq!(rc.settings.max_expanded_chart_bytes, 1_048_576);
        assert_eq!(rc.settings.max_index_bytes, 1);
        assert_eq!(rc.settings.ephemeral_cache.max_bytes, 1_048_576);
    }

    #[test]
    fn rejects_credentialed_upstream_alias_when_pull_auth_is_disabled() {
        let error = match parse_config(concat!(
            "storage:\n  type: memory\n",
            "aliases:\n",
            "  acme:\n    upstream: oci://asia-docker.pkg.dev/example-project/charts\n    auth: gcp\n",
        )) {
            Ok(_) => panic!("expected a credentialed alias without pull auth to be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();

        assert!(message.contains("acme"), "{message}");
        assert!(message.contains("auth.enabled"), "{message}");
        assert!(
            message.contains("allow_public_private_upstreams"),
            "{message}"
        );
    }

    #[test]
    fn accepts_credentialed_upstream_alias_with_pull_auth_enabled() {
        let rc = parse_config(concat!(
            "storage:\n  type: memory\n",
            "auth:\n  enabled: true\n  tokens: [\"sekrit\"]\n",
            "aliases:\n",
            "  acme:\n    upstream: oci://asia-docker.pkg.dev/example-project/charts\n    auth: gcp\n",
        ))
        .unwrap();
        assert_eq!(rc.aliases["acme"].auth, UpstreamAuthKind::Gcp);
    }

    #[test]
    fn accepts_credentialed_upstream_alias_with_explicit_public_opt_in() {
        let rc = parse_config(concat!(
            "storage:\n  type: memory\n",
            "allow_public_private_upstreams: true\n",
            "aliases:\n",
            "  acme:\n    upstream: oci://asia-docker.pkg.dev/example-project/charts\n    auth: gcp\n",
        ))
        .unwrap();
        assert!(rc.settings.allow_public_private_upstreams);
        assert_eq!(rc.aliases["acme"].auth, UpstreamAuthKind::Gcp);
    }

    #[test]
    fn anonymous_upstream_aliases_do_not_require_pull_auth() {
        let rc = parse_config(concat!(
            "storage:\n  type: memory\n",
            "aliases:\n",
            "  public:\n    upstream: oci://registry.example.com/team/charts\n",
        ))
        .unwrap();
        assert_eq!(rc.aliases["public"].auth, UpstreamAuthKind::None);
    }

    #[test]
    fn bundled_example_config_parses() {
        let rc = parse_config(include_str!("../../../examples/config.yaml")).unwrap();
        assert!(rc.aliases.contains_key("argo"));
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
        assert!(parse_config("storage:\n  type: s3\n").is_err());
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
            "auth:\n  enabled: true\n  tokens: [\"sekrit\"]\n",
            "aliases:\n",
            "  argo:\n    upstream: https://argoproj.github.io/argo-helm\n    store: true\n",
            "  acme:\n    upstream: oci://asia-docker.pkg.dev/example-project/charts\n    auth: gcp\n",
        );
        let rc = parse_config(yaml).unwrap();
        assert_eq!(rc.aliases.len(), 2);
        assert!(!rc.aliases["acme"].store);
        assert_eq!(
            rc.classic_alias_by_repo.get("argoproj.github.io/argo-helm"),
            Some(&"argo".to_string())
        );
    }
}
