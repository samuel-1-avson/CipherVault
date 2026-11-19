//! Short-alias CipherVault executable. Identical to `ciphervault`; the
//! library detects the invoked name from argv[0] for help and version.

fn main() {
    ciphervault_cli::run_cli();
}
