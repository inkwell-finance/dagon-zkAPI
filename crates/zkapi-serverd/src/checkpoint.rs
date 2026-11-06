//! Crash-safe checkpoint replacement shared by operator daemons.

use serde::Serialize;
use std::path::Path;

pub(crate) fn persist_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    drop(file);
    replace_file(&temporary, path)?;
    sync_parent(path)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(temporary, destination)
}

#[cfg(windows)]
fn replace_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that stay
    // alive for the duration of the Win32 call.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    // MOVEFILE_WRITE_THROUGH flushes the replacement. Windows does not permit
    // opening an ordinary directory with `File::open` for fsync.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_replacement_keeps_valid_json() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("checkpoint.json");
        persist_json(&path, &serde_json::json!({"generation": 1})).unwrap();
        persist_json(&path, &serde_json::json!({"generation": 2})).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(value["generation"], 2);
    }
}
