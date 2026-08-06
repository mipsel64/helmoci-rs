pub mod chart;
pub mod index;
pub mod rewrite;
pub mod tgz;

/// NotFound maps to 404, InvalidIndex/InvalidChart to 502, and ChartTooLarge to 413
/// at the server layer.
#[derive(Debug, thiserror::Error)]
pub enum HelmError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    InvalidIndex(String),
    #[error("{0}")]
    InvalidChart(String),
    /// A chart archive that busted a configured bound: the expansion budget, the
    /// per-file cap or the entry count. Distinct from `InvalidChart` so the size cap
    /// reaches its 413 without the server matching on message text.
    #[error("{0}")]
    ChartTooLarge(String),
}
