use crate::error::AppError;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait GcpTokenProvider: Send + Sync {
    async fn access_token(&self) -> Result<String, AppError>;
}

pub struct RealGcpTokenProvider {
    provider: Arc<dyn gcp_auth::TokenProvider>,
}

impl RealGcpTokenProvider {
    /// Fails fast at startup when ADC are unavailable.
    pub async fn new() -> eyre::Result<Self> {
        Ok(Self {
            provider: gcp_auth::provider().await?,
        })
    }
}

#[async_trait]
impl GcpTokenProvider for RealGcpTokenProvider {
    async fn access_token(&self) -> Result<String, AppError> {
        let token = self
            .provider
            .token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
            .map_err(|error| AppError::Upstream(format!("failed to obtain GCP token: {error}")))?;
        Ok(token.as_str().to_string())
    }
}
