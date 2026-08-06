use clap::Parser;
use helmoci::{config, gcp, metrics, routes, state};
use helmoci_core::resolver::UpstreamAuthKind;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "helmoci",
    about = "Classic Helm chart repositories served as an OCI registry"
)]
struct Args {
    /// Path to the YAML config file
    #[arg(long, env = "HELMOCI_CONFIG")]
    config: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .finish();
    // `set_global_default` rather than `init()` on purpose: `init()` also bridges
    // the `log` facade into tracing, and reqwest logs whole request URLs there at
    // debug level ("starting new connection: <url>"), which would put upstream
    // signed-URL query strings and chart references into the log the moment an
    // operator set RUST_LOG=debug. helmoci's own events are redacted by hand, so
    // dependency `log` records are dropped instead of being trusted; anything
    // needed from them has to be emitted, redacted, from helmoci.
    tracing::subscriber::set_global_default(subscriber)?;
    let args = Args::parse();
    let rc = config::load_config(&args.config)?;
    let storage = config::build_storage(&rc.settings.storage)?;
    let needs_gcp = rc
        .aliases
        .values()
        .any(|alias| alias.auth == UpstreamAuthKind::Gcp);
    let gcp_provider: Option<Arc<dyn gcp::GcpTokenProvider>> = if needs_gcp {
        Some(Arc::new(gcp::RealGcpTokenProvider::new().await?))
    } else {
        None
    };
    let _ = metrics::handle();
    let listen = rc.settings.listen.clone();
    let state = state::AppState::new(rc, storage, gcp_provider)?;
    let app = routes::build_router(state);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "helmoci listening");
    axum::serve(listener, app).await?;
    Ok(())
}
