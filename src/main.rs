use argon2::{
    Argon2, Params,
    password_hash::{PasswordHasher, SaltString},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use rpassword::prompt_password;
use std::env;
use std::fs::File;
use std::io::Seek;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use tar::Builder;
use tempfile::NamedTempFile;
use walkdir::WalkDir;
use zeroize::Zeroizing;
use zstd::stream::write::Encoder;

const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
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
        delete_files: bool,
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
    },
}

struct CustomProgressBar {}

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

fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let num_cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or_else(|e| {
            eprintln!("Can`t find cpu info: {}", e);
            1 // Default value
        });
    let num_cores: u32 = num_cores as u32;
    let params = Params::new(
        65536 * 4,      // memory size in KiB (64 MiB)
        100,            // time cost (number of iterations)
        num_cores,      // parallelism (number of threads)
        Some(KEY_SIZE), // output length in bytes (32 for XChaCha20)
    )
    .map_err(|e| -> Box<dyn std::error::Error> { format!("Params init failed?: {}", e).into() })?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = SaltString::encode_b64(salt).map_err(|e| -> Box<dyn std::error::Error> {
        format!("Salt creation failed: {}", e).into()
    })?;
    let hash = argon2.hash_password(password.as_bytes(), &salt).map_err(
        |e| -> Box<dyn std::error::Error> { format!("Hash creation failed: {}", e).into() },
    )?;
    Ok(hash.hash.unwrap().as_bytes().to_vec())
}

fn encrypt_file(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bar1 = CustomProgressBar::start("Encrypting...")?;
    let mut input = BufReader::new(File::open(input_path)?);
    let output = File::create(output_path)?;
    let mut output = BufWriter::new(output);

    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    output.write_all(&salt)?;

    let key = derive_key(password, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| -> Box<dyn std::error::Error> {
            format!("Cipher init failed: {}", e).into()
        })?;

    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let plaintext = &buffer[..n];

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        let ciphertext: Vec<u8> = cipher.encrypt(&nonce, plaintext.as_ref()).map_err(
            |e| -> Box<dyn std::error::Error> { format!("Frame encryption failed: {}", e).into() },
        )?;

        output.write_all(&nonce_bytes)?;
        output.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        output.write_all(&ciphertext)?;
    }

    output.flush()?;
    CustomProgressBar::finish(bar1, "Encryption successful");
    Ok(())
}

fn decrypt_file(
    input_path: &PathBuf,
    output: &File,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bar0 = CustomProgressBar::start("Decrypting...")?;
    let mut input = BufReader::new(File::open(input_path)?);
    let mut output = BufWriter::new(output);

    let mut salt = [0u8; SALT_SIZE];
    input.read_exact(&mut salt)?;

    let key = derive_key(password, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| -> Box<dyn std::error::Error> {
            format!("Cipher init failed: {}", e).into()
        })?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    let mut len_bytes = [0u8; 4];
    let mut ciphertext = Vec::new();

    loop {
        match input.read_exact(&mut nonce_bytes) {
            Ok(()) => {
                input.read_exact(&mut len_bytes)?;
                let len = u32::from_be_bytes(len_bytes) as usize;
                ciphertext.resize(len, 0);
                input.read_exact(&mut ciphertext)?;

                let plaintext = cipher
                    .decrypt(&XNonce::from(nonce_bytes), ciphertext.as_slice())
                    .map_err(|e| -> Box<dyn std::error::Error> {
                        format!("Frame decryption failed: {}", e).into()
                    })?;

                output.write_all(&plaintext)?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    output.flush()?;
    output.seek(std::io::SeekFrom::Start(0))?;
    CustomProgressBar::finish(bar0, "Decryption successful");
    Ok(())
}

fn extract(input_archive: &File, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let zstd_decoder = zstd::stream::read::Decoder::new(input_archive)?;
    let mut archive = tar::Archive::new(zstd_decoder);
    std::fs::create_dir_all(output_dir)?;
    archive.unpack(output_dir)?;
    Ok(())
}

fn archive(
    path: &PathBuf,
    archive_path: &File,
    remove_origins: bool,
    programm_dir: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let buf_writer = BufWriter::new(archive_path);
    let zstd_encoder = Encoder::new(buf_writer, 1)?;
    let mut tar_builder = Builder::new(zstd_encoder.auto_finish());

    if path.is_file() {
        if path != programm_dir {
            tar_builder.append_path_with_name(path, path.file_name().unwrap())?;
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            let relative_path = entry_path.strip_prefix(path)?;
            if relative_path.as_os_str().is_empty() {
                continue;
            }
            if entry_path.starts_with(programm_dir) {
                continue;
            }
            if entry_path.is_file() {
                tar_builder.append_path_with_name(entry_path, relative_path)?;
            } else if entry_path.is_dir() {
                tar_builder.append_dir(relative_path, entry_path)?;
            }
        }
    }
    if remove_origins {
        clear_directory(path, programm_dir)?;
    }
    tar_builder.into_inner()?;

    Ok(())
}

fn clear_directory(
    dir: &PathBuf,
    programm_dir: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() || path.is_symlink() {
            std::fs::remove_file(path)?;
        } else if path.is_dir() {
            if &path == programm_dir {
                continue;
            }
            std::fs::remove_dir_all(path)?;
        }
    }
    Ok(())
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
    let programm_dir = env::current_exe().unwrap().parent().unwrap().to_path_buf();
    match &cli.command {
        Commands::Encrypt {
            input,
            output,
            delete_files,
            file_name,
            full,
        } => {
            let input = input.clone().unwrap_or_else(|| {
                env::current_exe()
                    .unwrap()
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf()
            });
            let output = &output
                .clone()
                .unwrap_or_else(|| env::current_exe().unwrap().parent().unwrap().to_path_buf());
            let bar0 = CustomProgressBar::start("Archivating...")?;
            let temp_archive = NamedTempFile::new_in(output)?;
            archive(&input, temp_archive.as_file(), *delete_files, &programm_dir)?;
            CustomProgressBar::finish(bar0, "Archive successfully created");
            let temp_archive_path = temp_archive.into_temp_path();
            println!("Encrypting {} - {}", input.display(), &output.display()); //debug
            encrypt_file(
                &temp_archive_path.to_path_buf(),
                &output.join(create_file_name(file_name, *full)?),
                &get_password(true)?,
            )?;
        }
        Commands::Decrypt { input, output } => {
            let input = input.clone().unwrap_or_else(|| {
                get_files_to_decrypt(PathBuf::from(env::current_exe().unwrap().parent().unwrap()))
                    .unwrap_or_else(|err| {
                        eprintln!("Error getting file to decrypt: {}", err);
                        std::process::exit(1);
                    })
            });
            let output = &output.clone().unwrap_or_else(|| {
                env::current_exe()
                    .unwrap()
                    .parent()
                    .and_then(|p| p.parent())
                    .unwrap()
                    .to_path_buf()
            });
            let temp_archive =
                NamedTempFile::new_in(env::current_exe().unwrap().parent().unwrap())?;
            decrypt_file(&input, temp_archive.as_file(), &get_password(false)?)?;
            let bar1 = CustomProgressBar::start("Extracting...")?;
            extract(temp_archive.as_file(), output)?;
            CustomProgressBar::finish(bar1, "Archive successfully extracted");
        }
    }
    Ok(())
}
