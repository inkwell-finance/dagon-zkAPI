//! Generate a fresh, incompatible, single-party development setup for the
//! Solana Merkle-transition circuit.

fn main() -> anyhow::Result<()> {
    let directory = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: solana_transition_setup NEW_OUTPUT_DIRECTORY"))?;
    anyhow::ensure!(
        !std::path::Path::new(&directory).exists(),
        "refusing to overwrite an existing setup directory"
    );
    zkapi_proof::compact::setup_solana_transition(directory)
}
