use crate::config::RuntimeConfig;
use helmoci_storage::{EphemeralStorage, Storage};
use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub cfg: RuntimeConfig,
    pub storage: Arc<dyn Storage>,
    pub ephemeral: Arc<EphemeralStorage>,
    pub http: reqwest::Client,
    pub index_cache: moka::future::Cache<String, Arc<String>>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(cfg: RuntimeConfig, storage: Arc<dyn Storage>) -> anyhow::Result<SharedState> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()?;
        let index_cache = moka::future::Cache::builder()
            .max_capacity(512)
            .time_to_live(Duration::from_secs(cfg.settings.index_cache_ttl_secs))
            .build();
        let ephemeral = Arc::new(EphemeralStorage::new(
            cfg.settings.ephemeral_cache.max_bytes,
            Duration::from_secs(cfg.settings.ephemeral_cache.ttl_secs),
        ));
        Ok(Arc::new(AppState {
            cfg,
            storage,
            ephemeral,
            http,
            index_cache,
        }))
    }
}
