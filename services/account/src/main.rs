use ciphervault_account::{create_router, AccountState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data_dir = std::env::var_os("CIPHERVAULT_ACCOUNT_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("./account-data"));
    let bind =
        std::env::var("CIPHERVAULT_ACCOUNT_BIND").unwrap_or_else(|_| "127.0.0.1:8300".into());
    let state = AccountState::open(data_dir)?;
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("CipherVault account service listening on http://{bind}");
    axum::serve(listener, create_router(state)).await?;
    Ok(())
}
