pub static LICENSE: &str = r#"
MIT License

Copyright (c) 2025-2026 Cinnamon415

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"#;

pub static SOURCE: &str = r#"https://github.com/Cinnamon415/rpenc-cli"#;

pub mod config;
pub mod renc_core;

use clap::{Parser, Subcommand, crate_authors, crate_name, crate_version};
use config::Config;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::io::{self, BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;
use std::{env, fs};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = crate_name!(), author = crate_authors!(), version = crate_version!(), about, long_about = None)]
struct Cli {
    /// Override the path returned by env::current_exe().
    /// Used by rpenc.sh when launching via ld-linux or /tmp copy,
    /// where current_exe() would return wrong path.
    #[arg(long, hide = true)]
    real_exe: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short = 'i', long)]
        input: Option<PathBuf>,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(short = 'd', long)]
        delete_origins: bool,
        #[arg(short = 'n', long)]
        file_name: Option<String>,
        #[arg(short = 'f', long, requires = "file_name")]
        full: bool,
    },
    Decrypt {
        #[arg(short = 'i', long)]
        input: Option<PathBuf>,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(short = 'd', long)]
        remove_origin: bool,
    },
    License {},
}

/// Progress indicator that adapts to the environment:
/// - With TTY: animated spinner via indicatif
/// - Without TTY: plain text messages to stderr
enum Progress {
    Interactive(ProgressBar),
    Plain,
}

impl Progress {
    fn start(
        msg: &str,
        pb_config: &config::ProgressBarConfig,
    ) -> Result<Progress, Box<dyn std::error::Error>> {
        if io::stderr().is_terminal() {
            let bar = ProgressBar::new_spinner();
            bar.enable_steady_tick(Duration::from_millis(pb_config.tick_interval_ms));

            let tick_refs: Vec<&str> = pb_config.tick_strings.iter().map(|s| s.as_str()).collect();
            bar.set_style(
                ProgressStyle::with_template(&pb_config.template)
                    .map_err(|e| format!("Invalid progressbar template in config: {}", e))?
                    .tick_strings(&tick_refs),
            );
            bar.set_message(msg.to_string());
            Ok(Progress::Interactive(bar))
        } else {
            eprintln!("{}", msg);
            Ok(Progress::Plain)
        }
    }

    fn finish(self, msg: &str) {
        match self {
            Progress::Interactive(bar) => bar.finish_with_message(msg.to_string()),
            Progress::Plain => eprintln!("{}", msg),
        }
    }
}

/// Read password from TTY (interactive) or stdin (piped/scripted).
/// When stdin is not a terminal, reads one line per password from stdin without prompts.
fn read_password_line(prompt: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if io::stdin().is_terminal() {
        // Interactive: use rpassword to hide input
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    } else {
        // Non-interactive (pipe, redirect, script): read from stdin
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        // Remove trailing newline
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        if line.is_empty() {
            return Err("Empty password received from stdin".into());
        }
        Ok(Zeroizing::new(line))
    }
}

fn get_password(is_encrypting: bool) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    loop {
        let password = read_password_line("Enter your password: ")?;
        if is_encrypting {
            let password1 = read_password_line("Confirm password: ")?;
            if password != password1 {
                if !io::stdin().is_terminal() {
                    return Err("Passwords don't match (non-interactive mode, cannot retry)".into());
                }
                println!("Passwords don't match, try again")
            } else {
                return Ok(password);
            }
        } else {
            return Ok(password);
        }
    }
}

fn get_files_list_from_dir(
    dir: &PathBuf,
    extension: Option<&str>,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut file_paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = extension
                && path.extension().and_then(|s| s.to_str()) != Some(ext)
            {
                continue;
            }
            file_paths.push(path);
        }
    }
    Ok(file_paths)
}

fn get_files_to_decrypt(dir: PathBuf) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let file_list = get_files_list_from_dir(&dir, Some("enc"))?;
    if file_list.is_empty() {
        return Err(format!("No .enc files found in {}", &dir.display()).into());
    }
    let len = file_list.len();
    loop {
        println!("Choose file to decrypt:");
        for (n, file_path) in (1..).zip(file_list.iter()) {
            println!("  {}. {}", n, file_path.display());
        }
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        match input.parse::<usize>() {
            Ok(file_num) => match file_list.get(file_num - 1) {
                Some(file_to_decrypt) => {
                    return Ok(file_to_decrypt.clone());
                }
                None => {
                    eprintln!("Invalid file number. It must be from 1 to {}", len);
                    continue;
                }
            },
            Err(_e) => {
                eprintln!("Invalid input. Please enter a number.")
            }
        }
    }
}

fn sanitize_filename(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Reject path separators and traversal
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!(
            "Invalid filename '{}': must not contain '/', '\\', or '..'",
            name
        )
        .into());
    }
    // Reject empty or whitespace-only names
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Filename must not be empty".into());
    }
    Ok(trimmed.to_string())
}

fn create_file_name(
    name: &Option<String>,
    is_full: bool,
    default_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let name = name.as_deref().unwrap_or(default_name);
    let name = sanitize_filename(name)?;
    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    if !is_full {
        let file_name = format!(
            "{}-{}-{}.enc",
            name,
            now.as_secs(),
            rand::rng().random_range(1000..=9999)
        );
        return Ok(file_name);
    }
    let file_name = format!("{}.enc", name);
    Ok(file_name)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Use --real-exe if provided (from rpenc.sh fallback), otherwise env::current_exe()
    let exe_path = cli.real_exe.clone().unwrap_or_else(|| {
        env::current_exe().unwrap_or_else(|e| {
            eprintln!(
                "Error: cannot determine executable path: {}. \
                 Use --real-exe to specify it manually.",
                e
            );
            std::process::exit(1);
        })
    });

    // exe_path = .../rpenc/bin/rpenc-linux-x86_64
    // rpenc_dir = .../rpenc/          (parent of parent)
    // root_dir  = .../                (parent of rpenc_dir, i.e. USB root)
    let rpenc_dir = exe_path
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| {
            format!(
                "Error: executable path '{}' must be at least 2 levels deep (e.g. rpenc/bin/rpenc)",
                exe_path.display()
            )
        })?
        .to_path_buf();
    let root_dir = rpenc_dir
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    // Load config from rpenc/config.toml
    let cfg = Config::load(&rpenc_dir);

    let program_dir = rpenc_dir.clone();
    let mut custom_output = true;
    match &cli.command {
        Commands::Encrypt {
            input,
            output,
            delete_origins,
            file_name,
            full,
        } => {
            let input = input.clone().unwrap_or_else(|| root_dir.clone());
            let output = &output
                .clone()
                .unwrap_or_else(|| rpenc_dir.join(&cfg.defaults.output_dir));
            fs::create_dir_all(output)?;
            let bar0 = Progress::start("Archiving...", &cfg.progressbar)?;
            let temp_archive = NamedTempFile::new_in(output)?;
            renc_core::archive(
                &input,
                temp_archive.as_file(),
                *delete_origins,
                &program_dir,
                cfg.archive.compression_level,
            )?;
            bar0.finish("Archive successfully created");
            let temp_archive_path = temp_archive.into_temp_path();
            let password = get_password(true)?;
            let bar1 = Progress::start("Encrypting...", &cfg.progressbar)?;
            renc_core::encrypt_file(
                &temp_archive_path.to_path_buf(),
                &output.join(create_file_name(
                    file_name,
                    *full,
                    &cfg.defaults.default_name,
                )?),
                &password,
                Some(cfg.crypto.argon2_m_cost),
                Some(cfg.crypto.argon2_t_cost),
                Some(cfg.crypto.argon2_p_cost),
                Some(cfg.crypto.chunk_size),
            )?;
            bar1.finish("Encryption successful");
        }
        Commands::Decrypt {
            input,
            output,
            remove_origin,
        } => {
            let input = input.clone().unwrap_or_else(|| {
                get_files_to_decrypt(rpenc_dir.join(&cfg.defaults.output_dir)).unwrap_or_else(
                    |err| {
                        eprintln!("Error getting file to decrypt: {}", err);
                        std::process::exit(1);
                    },
                )
            });
            let output = &output.clone().unwrap_or_else(|| {
                custom_output = false;
                root_dir.clone()
            });
            if custom_output {
                fs::create_dir_all(output)?;
            }
            let encrypted_dir = rpenc_dir.join(&cfg.defaults.output_dir);
            fs::create_dir_all(&encrypted_dir)?;
            let temp_archive = NamedTempFile::new_in(&encrypted_dir)?;
            let password = get_password(false)?;
            let bar0 = Progress::start("Decrypting...", &cfg.progressbar)?;
            renc_core::decrypt_file(&input, temp_archive.as_file(), &password, *remove_origin)?;
            bar0.finish("Decryption successful");
            let bar1 = Progress::start("Extracting...", &cfg.progressbar)?;
            renc_core::extract(temp_archive.as_file(), output)?;
            bar1.finish("Archive successfully extracted");
        }
        Commands::License {} => {
            println!("{}", LICENSE);
            println!("\nSource of the program: {}", SOURCE)
        }
    }
    Ok(())
}
