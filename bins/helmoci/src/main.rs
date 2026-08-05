use clap::Parser;
use helmoci::{config, routes, state};
use helmoci_core::resolver::UpstreamAuthKind;
use std::sync::Arc;

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
    let args = Args::parse();
    let rc = config::load_config(&args.config)?;
    let storage = config::build_storage(&rc.settings.storage)?;
    let needs_gcp = rc
        .aliases
        .values()
        .any(|alias| alias.auth == UpstreamAuthKind::Gcp);
    let gcp_provider: Option<Arc<dyn helmoci::gcp::GcpTokenProvider>> = if needs_gcp {
        Some(Arc::new(helmoci::gcp::RealGcpTokenProvider::new().await?))
    } else {
        None
    };
    let listen = rc.settings.listen.clone();
    let state = state::AppState::new(rc, storage, gcp_provider)?;
    let app = routes::build_router(state);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("helmoci listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}
