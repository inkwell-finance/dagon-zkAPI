//! A release `dagon-zkapi` binary rejects `--adversary`: the adversary modes
//! exist only in drill builds (`--features adversary`), and even there the
//! server refuses them without debug assertions.
#![cfg(not(feature = "adversary"))]

use std::process::Command;

#[test]
fn the_release_binary_rejects_the_adversary_flag() {
    for mode in ["withhold", "random-anchor", "born-spent", "overcharge"] {
        let output = Command::new(env!("CARGO_BIN_EXE_dagon-zkapi"))
            .args(["serverd", "--adversary", mode])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{mode}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument '--adversary'"),
            "{mode}: {stderr}"
        );
    }
}
