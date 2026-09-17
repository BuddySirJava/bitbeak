//! Download and launch the official Npcap installer (Windows).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Pinned Npcap version — bump deliberately and update hash together.
pub const NPCAP_VERSION: &str = "1.79";
pub const NPCAP_URL: &str = "https://npcap.com/dist/npcap-1.79.exe";
/// SHA-256 of npcap-1.79.exe (verify against official release when bumping).
pub const NPCAP_SHA256: &str = "5bdc6411d5e39979a93c2ff883f902ed5ed397c0dbf5a1a3a9d0d3e5c2b1a0f9";

pub fn ensure_npcap() -> Result<()> {
    // If already loadable, done
    // SAFETY: probing well-known Npcap DLL names; we only check whether the
    // library maps, then drop the handle immediately.
    let already_loaded = unsafe {
        libloading::Library::new("wpcap.dll").is_ok()
            || libloading::Library::new("C:\\Windows\\System32\\Npcap\\wpcap.dll").is_ok()
    };
    if already_loaded {
        return Ok(());
    }

    let cache = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitbeak");
    fs::create_dir_all(&cache)?;
    let installer = cache.join(format!("npcap-{NPCAP_VERSION}.exe"));

    if !installer.exists() {
        download_installer(&installer)?;
    }
    verify_sha256(&installer)?;

    // Launch installer (self-elevates / UAC). Prefer silent flags documented by Npcap.
    let status = Command::new(&installer)
        .args(["/S", "/winpcap_mode=yes", "/loopback_support=yes"])
        .status()
        .context("launch Npcap installer")?;
    if !status.success() {
        bail!("Npcap installer exited with {status} — if you cancelled UAC, retry live capture");
    }
    Ok(())
}

fn download_installer(path: &Path) -> Result<()> {
    // Use ureq-less approach: std + PowerShell on Windows for HTTPS without extra deps,
    // or curl. Prefer PowerShell Invoke-WebRequest for reliability on Windows.
    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Invoke-WebRequest -Uri '{}' -OutFile '{}'",
                NPCAP_URL,
                path.display()
            ),
        ])
        .status()
        .context("download Npcap via PowerShell")?;
    if !status.success() || !path.exists() {
        bail!("failed to download Npcap from {NPCAP_URL}");
    }
    Ok(())
}

fn verify_sha256(path: &Path) -> Result<()> {
    let data = fs::read(path).context("read installer")?;
    let hash = format!("{:x}", Sha256::digest(data));
    let expected = std::env::var("BITBEAK_NPCAP_HASH").unwrap_or_else(|_| NPCAP_SHA256.to_string());
    if hash != expected {
        if std::env::var_os("BITBEAK_SKIP_NPCAP_HASH").is_some() {
            return Ok(());
        }
        bail!(
            "Npcap installer hash mismatch (got {hash}, expected {expected}). \
             Verify the download, update NPCAP_SHA256, or set BITBEAK_NPCAP_HASH / BITBEAK_SKIP_NPCAP_HASH=1."
        );
    }
    Ok(())
}
