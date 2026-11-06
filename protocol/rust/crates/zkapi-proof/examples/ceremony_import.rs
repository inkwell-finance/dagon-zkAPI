//! Convert the final snarkjs ceremony zkeys into zkAPI key artifacts.
//!
//! cargo run --release -p zkapi-proof --example ceremony_import -- ZKEY_DIR OUT_DIR MANIFEST MANIFEST_SHA256
//!
//! Expects `ZKEY_DIR/{request,withdrawal,transition}_final.zkey` and writes
//! `OUT_DIR/v2/*` (request/withdrawal keys, manifest, Solidity sources) and
//! `OUT_DIR/solana-transition-v1/*`. Existing non-empty target directories are
//! refused; nothing is ever written into the committed `protocol/setup`.

use anyhow::{bail, Result};

fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let (Some(zkey_dir), Some(out_dir), Some(manifest), Some(manifest_sha256), None) =
        (arguments.next(), arguments.next(), arguments.next(), arguments.next(), arguments.next())
    else {
        bail!("usage: ceremony_import ZKEY_DIR OUT_DIR MANIFEST MANIFEST_SHA256 (independently accepted)");
    };
    for circuit in zkapi_proof::ceremony::import_zkeys(&zkey_dir, &out_dir, &manifest, &manifest_sha256)? {
        println!(
            "{:<10} wires={} public={} domain={} contributions={} circuit_hash={}",
            circuit.id,
            circuit.zkey.n_vars,
            circuit.zkey.n_public,
            circuit.zkey.domain_size,
            circuit.zkey.contributions,
            hex::encode(circuit.zkey.circuit_hash)
        );
    }
    println!("wrote {out_dir}/v2 and {out_dir}/solana-transition-v1");
    Ok(())
}
