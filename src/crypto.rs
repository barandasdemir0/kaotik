//! Kripto ilkelleri: PBKDF2, Argon2id, HKDF, AES-256-GCM, nonce/salt üretimi, secure_zero.
use crate::error::{Error, Result};
use std::ptr::write_volatile;

const PBKDF2_ITERATIONS: u32 = 500_000;
pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// KDF türü: 0 = PBKDF2 (eski), 1 = Argon2id (önerilen)
pub const KDF_PBKDF2: u8 = 0;
pub const KDF_ARGON2: u8 = 1;

pub fn derive_key_pbkdf2(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key)
}

/// Argon2id ile anahtar türetme. OWASP önerisi: 64 MiB bellek, 3 iterasyon.
pub fn derive_key_argon2(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(65536) // 64 MiB (OWASP)
        .t_cost(3)
        .build()
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(key)
}

/// kdf: 0 = PBKDF2, 1 = Argon2id. Eski dosyalar için geri uyumlu.
pub fn derive_key(password: &str, salt: &[u8], kdf: u8) -> Result<[u8; KEY_LEN]> {
    match kdf {
        KDF_ARGON2 => derive_key_argon2(password, salt),
        _ => derive_key_pbkdf2(password, salt),
    }
}

/// Salt ile daha güçlü PRK; salt yoksa None (geri uyumlu).
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize, salt: Option<&[u8]>) -> Result<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(salt, prk);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).map_err(|_| Error::Crypto("HKDF expand failed".into()))?;
    Ok(okm)
}

pub fn aes_gcm_encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("Invalid key".into()))?;
    let ciphertext = cipher
        .encrypt(nonce.into(), plaintext)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(ciphertext)
}

pub fn aes_gcm_decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("Invalid key".into()))?;
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| Error::Crypto("Decryption failed".into()))?;
    Ok(plaintext)
}

pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(())
}

pub fn gen_salt() -> Result<[u8; SALT_LEN]> {
    let mut s = [0u8; SALT_LEN];
    random_bytes(&mut s)?;
    Ok(s)
}

pub fn gen_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    random_bytes(&mut n)?;
    Ok(n)
}

/// Chunk index ile benzersiz nonce: base_nonce'ın son 4 byte'ı ^ index (LE). GCM için her şifreleme farklı nonce.
pub fn nonce_for_chunk(base_nonce: &[u8; NONCE_LEN], chunk_index: u32) -> [u8; NONCE_LEN] {
    let mut n = *base_nonce;
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..4 {
        n[8 + i] ^= idx_bytes[i];
    }
    n
}

/// Sıfırlar hassas bellek; optimizer'ın silmeyi kaldırmasını önlemek için volatile yazım.
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf {
        unsafe { write_volatile(b, 0u8) };
    }
}
