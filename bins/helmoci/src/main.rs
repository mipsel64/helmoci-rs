use clap::Parser;
use helmoci::{config, routes, state};

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
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let rc = config::load_config(&args.config)?;
    let storage = config::build_storage(&rc.settings.storage)?;
    let listen = rc.settings.listen.clone();
    let state = state::AppState::new(rc, storage)?;
    let app = routes::build_router(state);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("helmoci listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}
