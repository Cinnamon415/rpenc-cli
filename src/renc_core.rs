pub static LICENSE: &str = r#"
MIT License

Copyright (c) 2025 Cinnamon415

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

pub static SOURCE: &str = r#"https://github.com/Cinnamon415/renc-core"#;

use argon2::{
    Argon2, Params,
    password_hash::{PasswordHasher, SaltString},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use std::fs;
use std::fs::File;
use std::io::Seek;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tar::Builder;
use walkdir::WalkDir;
use zstd::stream::write::Encoder;

const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let params = Params::new(
        65536 * 4,      // memory size in KiB
        10,             // time cost (number of iterations)
        4,              // parallelism (number of threads)
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

pub fn encrypt_file(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

pub fn decrypt_file(
    input_path: &PathBuf,
    output: &File,
    password: &str,
    remove_origin: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    if remove_origin {
        std::fs::remove_file(input_path)?;
    }
    Ok(())
}

pub fn extract(input_archive: &File, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let zstd_decoder = zstd::stream::read::Decoder::new(input_archive)?;
    let mut archive = tar::Archive::new(zstd_decoder);
    fs::create_dir_all(output_dir)?;
    archive.unpack(output_dir)?;
    Ok(())
}

pub fn archive(
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
