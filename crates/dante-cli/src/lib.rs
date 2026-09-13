//! Shared library surface for the `dante` CLI binary and the desktop shell
//! (`apps/dante-desktop`).
//!
//! It exposes [`serve`] — the engine wrapped in a tiny localhost HTTP/JSON API
//! plus an embedded single-file SPA — and the two small helpers `serve` needs.
//! The interactive `chat` client and the argument plumbing live in the binary
//! (`src/main.rs`), which also depends on this crate.

pub mod gifsearch;
pub mod serve;
pub mod unfurl;

use anyhow::Result;
use dante_identity::id::IdentityId;

/// Unix time in milliseconds (0 if the clock is before the epoch).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse a Crockford-base32 fingerprint or a 24-word phrase into the raw
/// `IdentityId` bytes.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let id = if s.contains(' ') {
        IdentityId::from_words(s)
    } else {
        IdentityId::from_base32(s)
    }
    .map_err(|_| anyhow::anyhow!("not a valid base32 or word-phrase fingerprint"))?;
    Ok(*id.as_bytes())
}

/// Write `bytes` to `path`, owner-only-readable on Unix (`0600`) — for the
/// sealed keystore, whose actual protection is the user's passphrase, not
/// the file mode, but a plain `std::fs::write` leaves it at the process
/// umask (typically `0644`, world-readable) with nothing else standing
/// between another local account and an offline passphrase-cracking attempt
/// on the file. Sets the mode both at creation and afterward, so a keystore
/// written by an older build before this existed is tightened on the very
/// next save too.
pub fn write_keystore_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn keystore_file_is_owner_only_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dante-keystore-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.keystore");

        write_keystore_file(&path, b"sealed bytes").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh keystore must be 0600, got {mode:o}");

        // A pre-existing file with looser permissions (e.g. written by a
        // build before this fix existed) must be tightened on the next save,
        // not just left as it was found.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_keystore_file(&path, b"sealed bytes v2").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "re-saving an existing looser-mode keystore must tighten it, got {mode:o}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
