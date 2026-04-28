use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_FILENAME: &str = "config.toml";

const DEFAULT_CONFIG: &str = r#"# rpenc configuration file
# This file is auto-generated with default values.
# Edit it to customize rpenc behavior.

[archive]
# zstd compression level: 1 (fastest) to 22 (smallest)
compression_level = 1

[progressbar]
# Template string for indicatif progress bar.
# Available placeholders: {spinner}, {msg}, {elapsed}, {bar}, {percent}, {bytes}, {total_bytes}
# Color syntax: {spinner:.blue}, {msg:.green}
template = "{spinner:.blue} {msg} {elapsed}"

# Spinner animation frames (last frame is the "finished" state)
tick_strings = ["▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸", "▪▪▪▪▪"]

# Tick interval in milliseconds
tick_interval_ms = 166

[defaults]
# Default output subdirectory for encrypted files (relative to rpenc dir)
output_dir = "encrypted"

# Default base name for encrypted files (when -n is not specified)
default_name = "encrypted-data"

[crypto]
# Argon2id memory cost in KiB (default: 65536 = 64 MB)
# Higher = more resistant to brute-force, but slower and uses more RAM
argon2_m_cost = 65536

# Argon2id time cost / iterations (default: 3)
argon2_t_cost = 3

# Argon2id parallelism / threads (default: 4)
argon2_p_cost = 4

# Plaintext chunk size in bytes (default: 65536 = 64 KB)
# Larger chunks = slightly faster, but use more RAM during encryption/decryption
chunk_size = 65536
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub archive: ArchiveConfig,
    #[serde(default)]
    pub progressbar: ProgressBarConfig,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveConfig {
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressBarConfig {
    #[serde(default = "default_template")]
    pub template: String,
    #[serde(default = "default_tick_strings")]
    pub tick_strings: Vec<String>,
    #[serde(default = "default_tick_interval")]
    pub tick_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsConfig {
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
    #[serde(default = "default_name")]
    pub default_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    #[serde(default = "default_argon2_m_cost")]
    pub argon2_m_cost: u32,
    #[serde(default = "default_argon2_t_cost")]
    pub argon2_t_cost: u32,
    #[serde(default = "default_argon2_p_cost")]
    pub argon2_p_cost: u32,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: u32,
}

// --- Default value functions ---

fn default_compression_level() -> i32 {
    1
}
fn default_template() -> String {
    "{spinner:.blue} {msg} {elapsed}".to_string()
}
fn default_tick_strings() -> Vec<String> {
    vec![
        "▹▹▹▹▹".to_string(),
        "▸▹▹▹▹".to_string(),
        "▹▸▹▹▹".to_string(),
        "▹▹▸▹▹".to_string(),
        "▹▹▹▸▹".to_string(),
        "▹▹▹▹▸".to_string(),
        "▪▪▪▪▪".to_string(),
    ]
}
fn default_tick_interval() -> u64 {
    166
}
fn default_output_dir() -> String {
    "encrypted".to_string()
}
fn default_name() -> String {
    "encrypted-data".to_string()
}
fn default_argon2_m_cost() -> u32 {
    65536
}
fn default_argon2_t_cost() -> u32 {
    3
}
fn default_argon2_p_cost() -> u32 {
    4
}
fn default_chunk_size() -> u32 {
    65536
}

// --- Trait implementations ---

impl Default for Config {
    fn default() -> Self {
        Self {
            archive: ArchiveConfig::default(),
            progressbar: ProgressBarConfig::default(),
            defaults: DefaultsConfig::default(),
            crypto: CryptoConfig::default(),
        }
    }
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            compression_level: default_compression_level(),
        }
    }
}

impl Default for ProgressBarConfig {
    fn default() -> Self {
        Self {
            template: default_template(),
            tick_strings: default_tick_strings(),
            tick_interval_ms: default_tick_interval(),
        }
    }
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            output_dir: default_output_dir(),
            default_name: default_name(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            argon2_m_cost: default_argon2_m_cost(),
            argon2_t_cost: default_argon2_t_cost(),
            argon2_p_cost: default_argon2_p_cost(),
            chunk_size: default_chunk_size(),
        }
    }
}

impl Config {
    /// Load config from `rpenc_dir/config.toml`.
    /// If the file doesn't exist, creates it with defaults.
    /// If parsing fails, prints a warning and returns defaults.
    pub fn load(rpenc_dir: &Path) -> Self {
        let config_path = rpenc_dir.join(CONFIG_FILENAME);

        if !config_path.exists() {
            // Create default config file
            if let Err(e) = fs::write(&config_path, DEFAULT_CONFIG) {
                eprintln!(
                    "Warning: could not create default config at {}: {}",
                    config_path.display(),
                    e
                );
            }
            return Config::default();
        }

        match fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!(
                        "Warning: failed to parse {}: {}. Using defaults.",
                        config_path.display(),
                        e
                    );
                    Config::default()
                }
            },
            Err(e) => {
                eprintln!(
                    "Warning: could not read {}: {}. Using defaults.",
                    config_path.display(),
                    e
                );
                Config::default()
            }
        }
    }

    /// Returns the path where the config file would be located.
    pub fn path(rpenc_dir: &Path) -> PathBuf {
        rpenc_dir.join(CONFIG_FILENAME)
    }
}
