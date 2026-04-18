use std::net::SocketAddr;

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = std::env::var("RUST_BACKEND_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9000".to_string())
        .parse()?;

    let listener = TcpListener::bind(addr).await?;
    println!("ISCY Rust backend listening on http://{}", addr);
    axum::serve(listener, iscy_backend::app_router()).await?;
    Ok(())
}
