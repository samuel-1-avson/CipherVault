//! Real CLI export -> independently pinned unattended inventory, using synthetic
//! vault data and loopback transport fixtures. Production enrollment is tested
//! separately by the operator authorization suite.
use std::{path::Path, sync::Arc};

async fn cli(root: &Path, args: &[&str]) -> String {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_ciphervault"))
        .args(args)
        .current_dir(root)
        .env("CIPHERVAULT_ACCOUNT_DIR", root.join("account"))
        .env("CIPHERVAULT_KEYSTORE_PATH", root.join("master.key"))
        .env("CIPHERVAULT_MASTER_KEY", "82".repeat(32))
        .env_remove("CIPHERVAULT_OPERATORS")
        .env_remove("CIPHERVAULT_OPERATOR_PINS")
        .env_remove("CIPHERVAULT_OPERATOR_SERVICE_TOKEN")
        .env_remove("CIPHERVAULT_DASHBOARD_URL")
        .env_remove("CIPHERVAULT_PROJECT")
        .env_remove("CIPHERVAULT_ENV")
        .env("NO_COLOR", "1")
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "CLI failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_exports_pinned_inventory_consumable_after_restart() {
    let root = std::env::temp_dir().join(format!(
        "cv-inventory-export-{:032x}",
        rand::random::<u128>()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut endpoints = Vec::new();
    let mut pins = Vec::new();
    let mut servers = Vec::new();
    for index in 0..3 {
        let key = ciphervault_crypto::generate_signing_key();
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let state = Arc::new(ciphervault_operator::OperatorState::new_with_security(
            format!("inventory-op-{index}"),
            root.join(format!("operator-{index}")),
            key,
            ciphervault_operator::state::OperatorSecurityConfig::legacy(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        pins.push(format!("{endpoint}={public_key}"));
        endpoints.push(endpoint);
        servers.push(tokio::spawn(async move {
            axum::serve(listener, ciphervault_operator::create_router(state))
                .await
                .unwrap();
        }));
    }
    let mut init_args = vec!["init", "--operators"];
    init_args.extend(endpoints.iter().map(String::as_str));
    cli(&root, &init_args).await;
    std::fs::write(
        root.join(".env"),
        "INVENTORY_SYNTHETIC_SECRET=must_not_be_in_public_export\n",
    )
    .unwrap();
    cli(&root, &["track", ".env"]).await;
    cli(&root, &["push"]).await;
    let exported = root.join("maintenance.json");
    let mut args = vec!["audit", "--export-inventory", exported.to_str().unwrap()];
    for pin in &pins {
        args.extend(["--operator-pin", pin.as_str()]);
    }
    let audit = cli(&root, &args).await;
    assert!(audit.contains("\"healthy\": true"), "{audit}");
    let bytes = std::fs::read(&exported).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("must_not_be_in_public_export"));
    let mut inventory = ciphervault_maintenance::scheduler::read_inventory(&exported).unwrap();
    assert_eq!(inventory.operator_keys.len(), 3);
    let db_path = root.join("maintenance.db");
    {
        let db = ciphervault_maintenance::MaintenanceDb::open(&db_path).unwrap();
        db.store_inventory(&inventory).unwrap();
    }
    let db = ciphervault_maintenance::MaintenanceDb::open(&db_path).unwrap();
    let report = ciphervault_maintenance::scheduler::run_inventory_job(&db, &mut inventory, None)
        .await
        .unwrap();
    assert!(report.healthy);
    assert_eq!(report.recoverable_operators.len(), 3);
    drop(db);
    for server in servers {
        server.abort();
        let _ = server.await;
    }
    std::fs::remove_dir_all(root).unwrap();
}
