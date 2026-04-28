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

pub static SOURCE: &str = r#"https://github.com/Cinnamon415/renc-core"#;

use argon2::{
    Argon2, Params,
    password_hash::{PasswordHasher, SaltString},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use std::fs;
use std::fs::File;
use std::io::Seek;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tar::Builder;
use walkdir::WalkDir;
use zeroize::Zeroizing;
use zstd::stream::write::Encoder;

const MAGIC: &[u8; 4] = b"RPEN";
const FORMAT_VERSION: u8 = 2;

// V1 hardcoded constants (for backward compatibility)
const V1_NONCE_SIZE: usize = 24;
const V1_SALT_SIZE: usize = 16;
const V1_KEY_SIZE: usize = 32;
const V1_CHUNK_SIZE: usize = 64 * 1024;
const V1_ARGON2_M_COST: u32 = 65536;
const V1_ARGON2_T_COST: u32 = 3;
const V1_ARGON2_P_COST: u32 = 4;

// ===== Algorithm ID enums =====

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CipherId {
    XChaCha20Poly1305 = 1,
    // Future: AES256GCM = 2, etc.
}

impl TryFrom<u8> for CipherId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CipherId::XChaCha20Poly1305),
            _ => Err(format!("Unknown cipher algorithm ID: {}. This file may require a newer version of rpenc", value).into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum KdfId {
    Argon2id = 1,
    // Future: Scrypt = 2, etc.
}

impl TryFrom<u8> for KdfId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(KdfId::Argon2id),
            _ => Err(format!("Unknown KDF algorithm ID: {}. This file may require a newer version of rpenc", value).into()),
        }
    }
}

// ===== File header =====

/// Holds all parameters needed to encrypt/decrypt a file.
/// Written into the .enc header so any rpenc instance can decrypt.
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub version: u8,
    pub cipher_id: CipherId,
    pub kdf_id: KdfId,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub key_size: u8,
    pub nonce_size: u8,
    pub salt_size: u8,
    pub chunk_size: u32,
    pub salt: Vec<u8>,
}

impl FileHeader {
    /// Create a new v2 header, generating a random salt.
    /// All parameters are optional — defaults match v1 values.
    pub fn new_v2(
        argon2_m_cost: Option<u32>,
        argon2_t_cost: Option<u32>,
        argon2_p_cost: Option<u32>,
        chunk_size: Option<u32>,
    ) -> Self {
        let salt_size: u8 = 16;
        let mut salt = vec![0u8; salt_size as usize];
        OsRng.fill_bytes(&mut salt);

        FileHeader {
            version: 2,
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            argon2_m_cost: argon2_m_cost.unwrap_or(V1_ARGON2_M_COST),
            argon2_t_cost: argon2_t_cost.unwrap_or(V1_ARGON2_T_COST),
            argon2_p_cost: argon2_p_cost.unwrap_or(V1_ARGON2_P_COST),
            key_size: 32,
            nonce_size: 24,
            salt_size,
            chunk_size: chunk_size.unwrap_or(V1_CHUNK_SIZE as u32),
            salt,
        }
    }

    /// Create a header with v1 hardcoded values (for reading v1 files).
    fn default_v1(salt: [u8; V1_SALT_SIZE]) -> Self {
        FileHeader {
            version: 1,
            cipher_id: CipherId::XChaCha20Poly1305,
            kdf_id: KdfId::Argon2id,
            argon2_m_cost: V1_ARGON2_M_COST,
            argon2_t_cost: V1_ARGON2_T_COST,
            argon2_p_cost: V1_ARGON2_P_COST,
            key_size: V1_KEY_SIZE as u8,
            nonce_size: V1_NONCE_SIZE as u8,
            salt_size: V1_SALT_SIZE as u8,
            chunk_size: V1_CHUNK_SIZE as u32,
            salt: salt.to_vec(),
        }
    }

    /// Write v2 header to output stream.
    pub fn write(&self, writer: &mut impl Write) -> Result<(), Box<dyn std::error::Error>> {
        writer.write_all(MAGIC)?;
        writer.write_all(&[FORMAT_VERSION])?;

        // Params block: cipher(1) + kdf(1) + m_cost(4) + t_cost(4) + p_cost(4)
        //             + key_size(1) + nonce_size(1) + salt_size(1) + chunk_size(4)
        //             + salt(salt_size)
        let header_len: u16 = 21 + self.salt_size as u16;
        writer.write_all(&header_len.to_be_bytes())?;

        writer.write_all(&[self.cipher_id as u8])?;
        writer.write_all(&[self.kdf_id as u8])?;
        writer.write_all(&self.argon2_m_cost.to_be_bytes())?;
        writer.write_all(&self.argon2_t_cost.to_be_bytes())?;
        writer.write_all(&self.argon2_p_cost.to_be_bytes())?;
        writer.write_all(&[self.key_size])?;
        writer.write_all(&[self.nonce_size])?;
        writer.write_all(&[self.salt_size])?;
        writer.write_all(&self.chunk_size.to_be_bytes())?;
        writer.write_all(&self.salt)?;

        Ok(())
    }

    /// Read header from input stream. Handles both v1 and v2 formats.
    pub fn read(reader: &mut impl Read) -> Result<Self, Box<dyn std::error::Error>> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err("Invalid file format: not an rpenc encrypted file".into());
        }

        let mut version_byte = [0u8; 1];
        reader.read_exact(&mut version_byte)?;
        let version = version_byte[0];

        match version {
            1 => {
                // V1: salt follows directly after version
                let mut salt = [0u8; V1_SALT_SIZE];
                reader.read_exact(&mut salt)?;
                Ok(FileHeader::default_v1(salt))
            }
            2 => {
                let mut header_len_bytes = [0u8; 2];
                reader.read_exact(&mut header_len_bytes)?;
                let header_len = u16::from_be_bytes(header_len_bytes) as usize;

                if header_len < 21 {
                    return Err(format!(
                        "Invalid v2 header: length {} is too short (minimum 21 bytes)",
                        header_len
                    ).into());
                }

                // Read the entire params block
                let mut header_data = vec![0u8; header_len];
                reader.read_exact(&mut header_data)?;

                let cipher_id = CipherId::try_from(header_data[0])?;
                let kdf_id = KdfId::try_from(header_data[1])?;
                let argon2_m_cost = u32::from_be_bytes(header_data[2..6].try_into()?);
                let argon2_t_cost = u32::from_be_bytes(header_data[6..10].try_into()?);
                let argon2_p_cost = u32::from_be_bytes(header_data[10..14].try_into()?);
                let key_size = header_data[14];
                let nonce_size = header_data[15];
                let salt_size = header_data[16];
                let chunk_size = u32::from_be_bytes(header_data[17..21].try_into()?);

                if salt_size == 0 {
                    return Err("Invalid header: salt_size is 0".into());
                }
                if 21 + salt_size as usize > header_len {
                    return Err(format!(
                        "Invalid header: salt_size {} exceeds header length {}",
                        salt_size, header_len
                    ).into());
                }

                let salt = header_data[21..21 + salt_size as usize].to_vec();

                // Validate params
                if argon2_m_cost < 8192 {
                    return Err(format!(
                        "Invalid argon2 m_cost: {} (minimum 8192 = 8 MB)", argon2_m_cost
                    ).into());
                }
                if argon2_t_cost < 1 {
                    return Err("Invalid argon2 t_cost: must be at least 1".into());
                }
                if argon2_p_cost < 1 {
                    return Err("Invalid argon2 p_cost: must be at least 1".into());
                }
                if chunk_size < 1024 {
                    return Err(format!(
                        "Invalid chunk_size: {} (minimum 1024 bytes)", chunk_size
                    ).into());
                }
                if chunk_size > 16 * 1024 * 1024 {
                    return Err(format!(
                        "Invalid chunk_size: {} (maximum 16 MB)", chunk_size
                    ).into());
                }

                Ok(FileHeader {
                    version,
                    cipher_id,
                    kdf_id,
                    argon2_m_cost,
                    argon2_t_cost,
                    argon2_p_cost,
                    key_size,
                    nonce_size,
                    salt_size,
                    chunk_size,
                    salt,
                })
            }
            _ => Err(format!(
                "Unsupported format version: {} (this rpenc supports versions 1-2). \
                 You may need a newer version of rpenc",
                version
            ).into()),
        }
    }

    /// Maximum encrypted chunk size (plaintext chunk + Poly1305 tag)
    pub fn max_ciphertext_size(&self) -> usize {
        self.chunk_size as usize + 16
    }
}

fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    key_size: usize,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let params = Params::new(
        m_cost,
        t_cost,
        p_cost,
        Some(key_size),
    )
    .map_err(|e| -> Box<dyn std::error::Error> { format!("Params init failed: {}", e).into() })?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = SaltString::encode_b64(salt).map_err(|e| -> Box<dyn std::error::Error> {
        format!("Salt creation failed: {}", e).into()
    })?;
    let hash = argon2.hash_password(password.as_bytes(), &salt).map_err(
        |e| -> Box<dyn std::error::Error> { format!("Hash creation failed: {}", e).into() },
    )?;
    Ok(Zeroizing::new(
        hash.hash
            .ok_or("Key derivation produced no hash output")?
            .as_bytes()
            .to_vec(),
    ))
}

pub fn encrypt_file(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
    argon2_m_cost: Option<u32>,
    argon2_t_cost: Option<u32>,
    argon2_p_cost: Option<u32>,
    chunk_size: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = BufReader::new(File::open(input_path)?);
    let output_file = File::create(output_path)?;
    let mut output = BufWriter::new(output_file);

    // Build and write v2 header with all crypto params + random salt
    let header = FileHeader::new_v2(argon2_m_cost, argon2_t_cost, argon2_p_cost, chunk_size);
    header.write(&mut output)?;

    let key = derive_key(
        password,
        &header.salt,
        header.argon2_m_cost,
        header.argon2_t_cost,
        header.argon2_p_cost,
        header.key_size as usize,
    )?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| -> Box<dyn std::error::Error> {
            format!("Cipher init failed: {}", e).into()
        })?;

    let nonce_size = header.nonce_size as usize;
    let mut chunk_index: u64 = 0;
    let mut buffer = vec![0u8; header.chunk_size as usize];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let plaintext = &buffer[..n];

        let mut nonce_bytes = vec![0u8; nonce_size];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Use chunk index as AAD to prevent reordering/deletion/duplication
        let aad = chunk_index.to_be_bytes();
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        let ciphertext: Vec<u8> =
            cipher
                .encrypt(nonce, payload)
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!("Frame encryption failed: {}", e).into()
                })?;

        output.write_all(&nonce_bytes)?;
        output.write_all(&(ciphertext.len() as u64).to_be_bytes())?;
        output.write_all(&ciphertext)?;

        chunk_index += 1;
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

    // Read header — automatically handles v1 and v2 formats
    let header = FileHeader::read(&mut input)?;

    let key = derive_key(
        password,
        &header.salt,
        header.argon2_m_cost,
        header.argon2_t_cost,
        header.argon2_p_cost,
        header.key_size as usize,
    )?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| -> Box<dyn std::error::Error> {
            format!("Cipher init failed: {}", e).into()
        })?;

    let max_chunk_size = header.max_ciphertext_size();
    let nonce_size = header.nonce_size as usize;

    let mut chunk_index: u64 = 0;
    let mut nonce_bytes = vec![0u8; nonce_size];
    let mut len_bytes = [0u8; 8];
    let mut ciphertext = Vec::new();

    loop {
        // Try to read the first byte of the nonce to distinguish
        // clean EOF (0 bytes read) from truncation (1+ bytes read)
        let mut first_byte = [0u8; 1];
        match input.read(&mut first_byte) {
            Ok(0) => {
                // Clean EOF — no more chunks
                if chunk_index == 0 {
                    return Err(
                        "Encrypted file contains no data chunks (file may be truncated after header)".into()
                    );
                }
                break;
            }
            Ok(_) => {
                nonce_bytes[0] = first_byte[0];
                // Read remaining bytes of nonce
                if let Err(_) = input.read_exact(&mut nonce_bytes[1..]) {
                    return Err(format!(
                        "Encrypted file is truncated at chunk {} (reading nonce): \
                         the file has trailing garbage or was not fully written to disk",
                        chunk_index
                    ).into());
                }
            }
            Err(e) => return Err(e.into()),
        }

        // Nonce read successfully — now read the rest of the chunk
        {
                if let Err(_e) = input.read_exact(&mut len_bytes) {
                    return Err(format!(
                        "Encrypted file is truncated at chunk {} (reading chunk length): \
                         the file may be corrupted or was not fully written to disk",
                        chunk_index
                    ).into());
                }
                let len = u64::from_be_bytes(len_bytes) as usize;

                if len > max_chunk_size {
                    return Err(format!(
                        "Encrypted file is corrupted at chunk {}: \
                         chunk size {} bytes exceeds maximum {} bytes. \
                         The file may be damaged or is not a valid rpenc file",
                        chunk_index, len, max_chunk_size
                    ).into());
                }

                ciphertext.resize(len, 0);
                if let Err(_e) = input.read_exact(&mut ciphertext) {
                    return Err(format!(
                        "Encrypted file is truncated at chunk {} \
                         (expected {} bytes of ciphertext, got EOF): \
                         the file may be corrupted or was not fully written to disk",
                        chunk_index, len
                    ).into());
                }

                // Verify chunk index via AAD to detect reordering/deletion/duplication
                let aad = chunk_index.to_be_bytes();
                let payload = Payload {
                    msg: ciphertext.as_slice(),
                    aad: &aad,
                };

                let plaintext = cipher
                    .decrypt(XNonce::from_slice(&nonce_bytes), payload)
                    .map_err(|e| -> Box<dyn std::error::Error> {
                        format!(
                            "Frame decryption failed at chunk {}: {} \
                             (wrong password or corrupted data)",
                            chunk_index, e
                        )
                        .into()
                    })?;

                output.write_all(&plaintext)?;
                chunk_index += 1;
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
    program_dir: &PathBuf,
    compression_level: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let buf_writer = BufWriter::new(archive_path);
    let zstd_encoder = Encoder::new(buf_writer, compression_level)?;
    let mut tar_builder = Builder::new(zstd_encoder.auto_finish());

    if path.is_file() {
        if path != program_dir {
            let fname = path
                .file_name()
                .ok_or("Input file has no filename component")?;
            tar_builder.append_path_with_name(path, fname)?;
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .follow_links(false) // never follow symlinks
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let entry_path = entry.path();
            let relative_path = entry_path.strip_prefix(path)?;
            if relative_path.as_os_str().is_empty() {
                continue;
            }
            if entry_path.starts_with(program_dir) {
                continue;
            }
            // Skip symlinks — they can point outside the input directory
            if entry_path.is_symlink() {
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
        clear_directory(path, program_dir)?;
    }
    tar_builder.into_inner()?;

    Ok(())
}

fn clear_directory(dir: &PathBuf, program_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() || path.is_symlink() {
            std::fs::remove_file(path)?;
        } else if path.is_dir() {
            if &path == program_dir {
                continue;
            }
            std::fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}
