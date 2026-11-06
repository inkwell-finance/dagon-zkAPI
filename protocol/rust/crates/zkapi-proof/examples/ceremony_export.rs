//! Export the three zkAPI circuits as snarkjs `.r1cs` files for a trusted-setup
//! ceremony.
//!
//! cargo run --release -p zkapi-proof --example ceremony_export -- OUT_DIR
//!
//! Writes `OUT_DIR/{request,withdrawal,transition}.r1cs` and
//! `OUT_DIR/circuits.json` (constraint counts and the Powers-of-Tau power
//! `snarkjs zkey new` needs). The output is deterministic.

use anyhow::{bail, Result};

fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let (Some(directory), None) = (arguments.next(), arguments.next()) else {
        bail!("usage: ceremony_export OUT_DIR");
    };
    for report in zkapi_proof::ceremony::export_r1cs(&directory)? {
        println!(
            "{:<10} constraints={} instanceVariables={} witnessVariables={} ptauPowerNeeded={}",
            report.id,
            report.constraints,
            report.instance_variables,
            report.witness_variables,
            report.ptau_power_needed
        );
    }
    Ok(())
}
