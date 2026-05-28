// TEE Attestation Service Policy Library - Key Loader
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// RSA private key loading from PEM files (PKCS#8 or traditional PKCS#1).

use std::path::Path;

use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// RSA signing key for policy signatures.
pub struct SigningKey {
    pub(crate) private_key: RsaPrivateKey,
}

impl SigningKey {
    /// Load an RSA private key from a PEM file.
    ///
    /// Supports PKCS#8 (encrypted and unencrypted), traditional OpenSSL
    /// PKCS#1 (unencrypted), and legacy OpenSSL encrypted PEM files
    /// (PKCS#1 with Proc-Type/DEK-Info headers, AES-128-CBC or AES-256-CBC).
    ///
    /// The raw PEM data is zeroized after parsing so it does not
    /// linger in process memory.
    ///
    /// # Arguments
    /// * `path` - Path to the PEM-encoded private key file.
    /// * `password` - Optional passphrase for encrypted keys.
    pub fn from_file(path: impl AsRef<Path>, password: Option<&str>) -> Result<Self> {
        let mut pem_data =
            std::fs::read_to_string(path.as_ref()).map_err(|e| Error::KeyFileError {
                path: path.as_ref().display().to_string(),
                source: e,
            })?;

        let result = if let Some(pass) = password {
            // Try encrypted PKCS#8 first, then fall back to legacy OpenSSL encrypted PEM
            RsaPrivateKey::from_pkcs8_encrypted_pem(&pem_data, pass.as_bytes())
                .map_err(|e| {
                    Error::SigningError(format!(
                        "failed to decrypt key from {}: {}",
                        path.as_ref().display(),
                        e
                    ))
                })
                .or_else(|pkcs8_err| {
                    log::debug!("PKCS#8 encrypted parse failed, trying legacy format: {pkcs8_err}");
                    decrypt_legacy_openssl_pem(&pem_data, pass).map_err(|e| {
                        Error::SigningError(format!(
                            "failed to load key from {}: not valid PKCS#8 encrypted ({}), \
                             and legacy OpenSSL decrypt also failed: {}",
                            path.as_ref().display(),
                            pkcs8_err,
                            e,
                        ))
                    })
                })
        } else {
            // Try unencrypted PKCS#8, then fall back to PKCS#1
            RsaPrivateKey::from_pkcs8_pem(&pem_data)
                .or_else(|_| {
                    use rsa::pkcs1::DecodeRsaPrivateKey;
                    RsaPrivateKey::from_pkcs1_pem(&pem_data)
                })
                .map_err(|e| {
                    Error::SigningError(format!(
                        "failed to load key from {}: {}",
                        path.as_ref().display(),
                        e
                    ))
                })
        };

        // Zeroize the raw PEM regardless of success or failure
        pem_data.zeroize();

        Ok(Self {
            private_key: result?,
        })
    }
}

/// OpenSSL `EVP_BytesToKey` with MD5 and iteration count 1.
///
/// Derives `key_len` bytes of key material from `password` and `salt`.
fn evp_bytes_to_key(password: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};

    let mut key = Vec::with_capacity(key_len);
    let mut prev_hash: Option<[u8; 16]> = None;

    while key.len() < key_len {
        let mut hasher = Md5::new();
        if let Some(ref h) = prev_hash {
            hasher.update(h);
        }
        hasher.update(password);
        hasher.update(salt);
        let hash: [u8; 16] = hasher.finalize().into();
        key.extend_from_slice(&hash);
        prev_hash = Some(hash);
    }

    key.truncate(key_len);
    key
}

/// Decrypt a legacy OpenSSL encrypted PEM private key.
///
/// Handles PKCS#1 PEM files with `Proc-Type: 4,ENCRYPTED` and `DEK-Info`
/// headers (the format produced by `openssl genrsa -aes256` or the Python
/// `cryptography` library with `BestAvailableEncryption`).
///
/// Supports AES-128-CBC and AES-256-CBC ciphers.
fn decrypt_legacy_openssl_pem(pem_data: &str, password: &str) -> Result<RsaPrivateKey> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

    let parsed = pem::parse(pem_data)
        .map_err(|e| Error::SigningError(format!("failed to parse PEM: {e}")))?;

    if parsed.tag() != "RSA PRIVATE KEY" {
        return Err(Error::SigningError(
            "not a legacy OpenSSL encrypted PEM (expected RSA PRIVATE KEY)".into(),
        ));
    }

    // Extract DEK-Info from PEM headers
    let dek_info = parsed
        .headers()
        .get("DEK-Info")
        .ok_or_else(|| Error::SigningError("missing DEK-Info in encrypted PEM".into()))?
        .to_owned();

    let (cipher_name, init_vec_hex) = dek_info
        .split_once(',')
        .ok_or_else(|| Error::SigningError("malformed DEK-Info header".into()))?;

    let init_vec: Vec<u8> = (0..init_vec_hex.trim().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&init_vec_hex.trim()[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| {
            Error::SigningError(format!(
                "invalid initialisation vector hex in DEK-Info: {e}"
            ))
        })?;

    let encrypted_der = parsed.into_contents();

    // Derive key material (EVP_BytesToKey, salt = first 8 bytes of init_vec)
    let salt = &init_vec[..8];

    let decrypted_der = match cipher_name.trim() {
        "AES-256-CBC" => {
            let key = evp_bytes_to_key(password.as_bytes(), salt, 32);
            let mut buf = encrypted_der;
            cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &init_vec)
                .map_err(|e| Error::SigningError(format!("cipher init: {e}")))?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| Error::SigningError("decryption failed (wrong passphrase?)".into()))?
                .to_vec()
        }
        "AES-128-CBC" => {
            let key = evp_bytes_to_key(password.as_bytes(), salt, 16);
            let mut buf = encrypted_der;
            cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &init_vec)
                .map_err(|e| Error::SigningError(format!("cipher init: {e}")))?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| Error::SigningError("decryption failed (wrong passphrase?)".into()))?
                .to_vec()
        }
        other => {
            return Err(Error::SigningError(format!(
                "unsupported legacy PEM cipher: {other} \
                 (convert with: openssl pkey -in KEY.pem -out KEY-pkcs8.pem)"
            )));
        }
    };

    // Parse the decrypted DER as PKCS#1
    use rsa::pkcs1::DecodeRsaPrivateKey;
    RsaPrivateKey::from_pkcs1_der(&decrypted_der).map_err(|e| {
        Error::SigningError(format!("failed to parse decrypted key as PKCS#1 DER: {e}"))
    })
}
