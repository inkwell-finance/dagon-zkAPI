//! zkAPI v2 compact Groth16 circuits and native proof interface.

pub mod ceremony;
pub mod circom_reduction;
pub mod compact;
pub mod groth16;
pub mod snarkjs_zkey;

#[cfg(test)]
mod test_support;

/// Fresh keys for host regression tests; never compiled into normal clients.
#[cfg(any(test, feature = "test-utils"))]
pub fn test_setup() -> &'static std::path::Path {
    static SETUP: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        if let Some(path) = std::env::var_os("ZKAPI_TEST_SETUP") {
            return path.into();
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("zkapi-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        compact::setup(&path).unwrap();
        path
    });
    &SETUP
}
