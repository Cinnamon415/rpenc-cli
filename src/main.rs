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

pub mod renc_core;

use clap::{Parser, Subcommand, crate_authors, crate_name, crate_version};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use rpassword::prompt_password;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;
use std::{env, fs};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = crate_name!(), author = crate_authors!(), version = crate_version!(), about, long_about = None)]
struct Cli {
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

struct CustomProgressBar;

impl CustomProgressBar {
    fn start(msg: &str) -> Result<ProgressBar, Box<dyn std::error::Error>> {
        let bar = ProgressBar::new_spinner();
        bar.enable_steady_tick(Duration::from_millis(166));
        bar.set_style(
            ProgressStyle::with_template("{spinner:.blue} {msg} {elapsed}")
                .unwrap()
                // https://github.com/sindresorhus/cli-spinners/blob/master/spinners.json
                .tick_strings(&[
                    "▹▹▹▹▹",
                    "▸▹▹▹▹",
                    "▹▸▹▹▹",
                    "▹▹▸▹▹",
                    "▹▹▹▸▹",
                    "▹▹▹▹▸",
                    "▪▪▪▪▪",
                ]),
        );
        bar.set_message(msg.to_string());
        Ok(bar)
    }
    fn finish(bar: ProgressBar, msg: &str) {
        bar.finish_with_message(msg.to_string());
    }
}

fn get_password(is_encrypting: bool) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    loop {
        let password = Zeroizing::new(prompt_password("Enter your password: ")?);
        if is_encrypting {
            let password1 = Zeroizing::new(prompt_password("Confirm password: ")?);
            if password != password1 {
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
        let mut n = 1;
        println!("Choose file to decrypt:");
        for file_path in &file_list {
            println!("  {}. {}", n, file_path.display());
            n += 1;
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

fn create_file_name(
    name: &Option<String>,
    is_full: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let name = name.as_deref().unwrap_or("encrypted-data");
    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    if !is_full {
        let file_name = format!(
            "{}-{:?}-{}.enc",
            name,
            now,
            rand::rng().random_range(1000..=9999)
        );
        return Ok(file_name);
    }
    let file_name = format!("{}.enc", name);
    Ok(file_name)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let programm_dir = env::current_exe()
        .unwrap()
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    let mut custom_output = true;
    match &cli.command {
        Commands::Encrypt {
            input,
            output,
            delete_origins,
            file_name,
            full,
        } => {
            let input = input.clone().unwrap_or_else(|| {
                env::current_exe()
                    .unwrap()
                    .parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf()
            });
            let output = &output.clone().unwrap_or_else(|| {
                env::current_exe()
                    .unwrap()
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap()
                    .join("encrypted")
            });
            fs::create_dir_all(output)?;
            let bar0 = CustomProgressBar::start("Archivating...")?;
            let temp_archive = NamedTempFile::new_in(output)?;
            renc_core::archive(
                &input,
                temp_archive.as_file(),
                *delete_origins,
                &programm_dir,
            )?;
            CustomProgressBar::finish(bar0, "Archive successfully created");
            let temp_archive_path = temp_archive.into_temp_path();
            println!("Encrypting {} - {}", input.display(), &output.display()); //debug
            let bar1 = CustomProgressBar::start("Encrypting...")?;
            renc_core::encrypt_file(
                &temp_archive_path.to_path_buf(),
                &output.join(create_file_name(file_name, *full)?),
                &get_password(true)?,
            )?;
            CustomProgressBar::finish(bar1, "Encryption successful");
        }
        Commands::Decrypt {
            input,
            output,
            remove_origin,
        } => {
            let input = input.clone().unwrap_or_else(|| {
                get_files_to_decrypt(
                    env::current_exe()
                        .unwrap()
                        .parent()
                        .and_then(|p| p.parent())
                        .unwrap()
                        .join("encrypted"),
                )
                .unwrap_or_else(|err| {
                    eprintln!("Error getting file to decrypt: {}", err);
                    std::process::exit(1);
                })
            });
            let output = &output.clone().unwrap_or_else(|| {
                custom_output = false;
                env::current_exe()
                    .unwrap()
                    .parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.parent())
                    .unwrap()
                    .to_path_buf()
            });
            if custom_output {
                fs::create_dir_all(output)?;
            }
            let temp_archive = NamedTempFile::new_in(
                env::current_exe()
                    .unwrap()
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap()
                    .join("encrypted"),
            )?;
            let bar0 = CustomProgressBar::start("Decrypting...")?;
            renc_core::decrypt_file(
                &input,
                temp_archive.as_file(),
                &get_password(false)?,
                *remove_origin,
            )?;
            CustomProgressBar::finish(bar0, "Decryption successful");
            let bar1 = CustomProgressBar::start("Extracting...")?;
            renc_core::extract(temp_archive.as_file(), output)?;
            CustomProgressBar::finish(bar1, "Archive successfully extracted");
            println!("Archive succesfully extracted");
        }
        Commands::License {} => {
            println!("{}", LICENSE);
        }
    }
    Ok(())
}
