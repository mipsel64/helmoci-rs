use clap::Parser;
use helmoci::{config, gcp, metrics, routes, state};
use helmoci_core::resolver::UpstreamAuthKind;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "helmoci",
    version = helmoci_info::version(),
    about = "Classic Helm chart repositories served as an OCI registry"
)]
struct Args {
    /// Path to the YAML config file
    #[arg(long, env = "HELMOCI_CONFIG")]
    config: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let rc = config::load_config(&args.config)?;

    config::init_logging(&rc.settings.log)?;

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
