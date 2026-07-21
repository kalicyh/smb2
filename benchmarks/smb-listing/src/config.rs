//! Target configuration for the listing probe.
//!
//! Reuses the same TOML shape as the sibling `benchmarks/smb` harness, so a
//! single `config.toml` describes the NAS for both. By default we read the
//! sibling's `benchmarks/smb/config.toml` (no credential duplication); override
//! the path with `SMB_LISTING_CONFIG` or `--config <path>`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct BenchConfig {
    pub targets: Vec<Target>,
}

#[derive(Deserialize, Clone)]
pub struct Target {
    pub name: String,
    pub host: String,
    pub share: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub guest: bool,
    // These two exist only so we can parse the sibling harness's `config.toml`
    // unchanged; the listing probe never uses them.
    #[serde(default)]
    #[allow(dead_code)]
    pub native_mount: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub max_chunk_kb: Option<u32>,
}

impl BenchConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Can't read {}: {e}", path.display()))?;
        toml::from_str(&content).map_err(|e| format!("Invalid TOML in {}: {e}", path.display()))
    }

    /// Pick a target by name, or the first one when `name` is `None`.
    pub fn pick(&self, name: Option<&str>) -> Result<Target, String> {
        match name {
            Some(n) => self
                .targets
                .iter()
                .find(|t| t.name == n)
                .cloned()
                .ok_or_else(|| format!("No target named '{n}' in config")),
            None => self
                .targets
                .first()
                .cloned()
                .ok_or_else(|| "Config has no targets".to_string()),
        }
    }
}

/// Default config path: the sibling `benchmarks/smb/config.toml`.
pub fn default_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../smb/config.toml")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../smb/config.toml"))
}
