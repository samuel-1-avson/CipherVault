//! Canonical CipherVault executable. All behavior lives in the
//! `ciphervault_cli` library; this shim only forwards to its entry point
//! (the invoked name is still detected from argv[0] inside the library).

fn main() {
    ciphervault_cli::run_cli();
}
