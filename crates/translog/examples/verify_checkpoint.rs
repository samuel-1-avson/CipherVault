//! Independently verifies a witnessed checkpoint fetched from an operator.
//!
//! ```text
//! cargo run -p ciphervault-translog --example verify_checkpoint -- \
//!     <checkpoint file> <origin> <log vkey> <quorum> [<witness vkey>...]
//! ```
//!
//! Exits 0 only when the log's Ed25519 signature verifies under the pinned
//! log key, the checkpoint names `origin`, and at least `quorum` distinct
//! pinned witnesses cosigned it. Prints the size, root and each verified
//! cosignature. Keys come from the command line (pin them out of band), never
//! from the checkpoint itself.

use ciphervault_translog::checkpoint::open_checkpoint;
use ciphervault_translog::cosignature::WitnessVerifier;
use ciphervault_translog::note::Ed25519NoteVerifier;
use ciphervault_translog::NoteVerifier;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        eprintln!("usage: verify_checkpoint <checkpoint file> <origin> <log vkey> <quorum> [<witness vkey>...]");
        return ExitCode::from(2);
    }
    let msg = match std::fs::read(&args[0]) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("read {}: {e}", args[0]);
            return ExitCode::from(2);
        }
    };
    let log_key = match Ed25519NoteVerifier::from_vkey(&args[2]) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("bad log vkey: {e}");
            return ExitCode::from(2);
        }
    };
    let quorum: usize = match args[3].parse() {
        Ok(q) => q,
        Err(_) => {
            eprintln!("quorum must be a number");
            return ExitCode::from(2);
        }
    };
    let mut witnesses = Vec::new();
    for vkey in &args[4..] {
        match WitnessVerifier::from_vkey(vkey) {
            Ok(w) => witnesses.push(w),
            Err(e) => {
                eprintln!("bad witness vkey: {e}");
                return ExitCode::from(2);
            }
        }
    }
    match open_checkpoint(&msg, &args[1], &log_key, &witnesses) {
        Ok(verified) => {
            let cp = verified.checkpoint();
            let root: String = cp.root().iter().map(|b| format!("{b:02x}")).collect();
            println!("origin={} size={} root={}", cp.origin(), cp.size(), root);
            println!("log signature: OK ({})", log_key.name());
            for cosig in verified.cosignatures() {
                println!(
                    "cosignature: OK {} key_id={:08x} timestamp={}",
                    cosig.name(),
                    cosig.key_id(),
                    cosig.timestamp()
                );
            }
            let have = verified.cosignatures().len();
            if have >= quorum {
                println!("witness quorum: OK ({have} of {quorum} required)");
                ExitCode::SUCCESS
            } else {
                println!("witness quorum: NOT MET ({have} of {quorum} required)");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            println!("checkpoint verification FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}
