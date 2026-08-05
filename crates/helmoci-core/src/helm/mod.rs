pub mod chart;
pub mod index;
pub mod tgz;

/// NotFound maps to 404; InvalidIndex/InvalidChart map to 502 at the server layer.
#[derive(Debug, thiserror::Error)]
pub enum HelmError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    InvalidIndex(String),
    #[error("{0}")]
    InvalidChart(String),
}
