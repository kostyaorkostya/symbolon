//! Atomic file write: tempfile → fsync → rename → fsync parent.
//!
//! The on-disk shape of every state file (`clients.json`,
//! `/var/lib/symbolon/psks`, the runtime pidfile) is expected to be
//! crash-coherent: a daemon SIGKILL mid-write must leave the file
//! either at its previous content or at the new content, never
//! partial. The sequence here is the standard Unix recipe for that
//! invariant — followed by a parent-directory fsync so the rename
//! itself reaches the disk before the syscall returns.

use std::path::Path;

use compio::BufResult;

/// Write `content` to `path` atomically with file mode `mode`.
/// Creates `path` if it doesn't exist; replaces it if it does.
/// Cleans up the tempfile on rename failure.
pub async fn atomic_write(path: &Path, content: Vec<u8>, mode: u32) -> std::io::Result<()> {
    use compio::io::AsyncWriteAtExt;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"))?
        .to_path_buf();
    let base = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let tmp = dir.join(format!(
        "{}.tmp.{}",
        base.to_string_lossy(),
        ulid::Ulid::new()
    ));
    {
        let mut f = compio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .await?;
        let BufResult(res, _) = f.write_all_at(content, 0).await;
        res?;
        f.sync_all().await?;
    }
    if let Err(e) = compio::fs::rename(&tmp, path).await {
        let _ = compio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    // Parent-dir fsync: open the dir as a File and call sync_all.
    // compio::fs::File::open defaults to O_RDONLY which is the right
    // mode for fsync-only on a directory.
    compio::fs::File::open(&dir).await?.sync_all().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[compio::test]
    async fn atomic_write_round_trip_with_mode() {
        let tmp = std::env::temp_dir();
        let path = tmp.join(format!("symbolon-atomic-test-{}", ulid::Ulid::new()));
        atomic_write(&path, b"hello\n".to_vec(), 0o600)
            .await
            .expect("write");
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes, b"hello\n");
        let meta = std::fs::metadata(&path).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        atomic_write(&path, b"world\n".to_vec(), 0o640)
            .await
            .expect("rewrite");
        let bytes = std::fs::read(&path).expect("reread");
        assert_eq!(bytes, b"world\n");
        let meta = std::fs::metadata(&path).expect("metadata 2");
        assert_eq!(meta.permissions().mode() & 0o777, 0o640);
        let _ = std::fs::remove_file(&path);
    }
}
