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
/// Argon2id güçlendirilmiş profil (v6+): 256 MiB bellek, 4 iterasyon. GPU/ASIC kaba kuvvetini pahalılaştırır.
pub const KDF_ARGON2_STRONG: u8 = 2;
/// Yeni dosyalar için varsayılan KDF.
pub const KDF_DEFAULT: u8 = KDF_ARGON2_STRONG;

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

/// Argon2id güçlü profil: 256 MiB, t=4.
pub fn derive_key_argon2_strong(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(262_144)
        .t_cost(4)
        .p_cost(1)
        .build()
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(key)
}

/// kdf: 0 = PBKDF2, 1 = Argon2id, 2 = Argon2id güçlü. Bilinmeyen değer reddedilir.
pub fn derive_key(password: &str, salt: &[u8], kdf: u8) -> Result<[u8; KEY_LEN]> {
    // Fuzz derlemesinde (cargo fuzz, cfg(fuzzing)) Argon2 maliyeti ayrıştırıcıları test etmeyi imkânsızlaştırır.
    // Ucuz yol yalnızca fuzz hedefi bu değişkeni ayarladığında açılır: yanlışlıkla `--cfg fuzzing`
    // ile derlenen normal bir sürüm yine gerçek Argon2 kullanır.
    #[cfg(fuzzing)]
    if kdf <= KDF_ARGON2_STRONG && std::env::var_os("KAOTIK_FUZZ_CHEAP_KDF").is_some() {
        let okm = hkdf_expand(password.as_bytes(), &[kdf], KEY_LEN, Some(salt))?;
        return Ok(okm.try_into().expect("KEY_LEN"));
    }
    match kdf {
        KDF_PBKDF2 => derive_key_pbkdf2(password, salt),
        KDF_ARGON2 => derive_key_argon2(password, salt),
        KDF_ARGON2_STRONG => derive_key_argon2_strong(password, salt),
        _ => Err(Error::Format("Unknown KDF".into())),
    }
}

/// Ana anahtardan bağlama özel 32 baytlık alt anahtar (HKDF-SHA256).
pub fn subkey(master: &[u8; KEY_LEN], info: &[u8]) -> Result<[u8; KEY_LEN]> {
    let okm = hkdf_expand(master, info, KEY_LEN, None)?;
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&okm);
    Ok(k)
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Sabit zamanlı karşılaştırma.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).unwrap_u8() == 1
}

/// Salt ile daha güçlü PRK; salt yoksa None (geri uyumlu).
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize, salt: Option<&[u8]>) -> Result<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(salt, prk);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| Error::Crypto("HKDF expand failed".into()))?;
    Ok(okm)
}

pub fn aes_gcm_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
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

pub fn aes_gcm_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
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

/// AES-256-GCM, ek doğrulanmış veri (AAD) ile: başlık/metaveri değiştirilirse çözme başarısız olur.
pub fn aes_gcm_encrypt_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm,
    };
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("Invalid key".into()))?;
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(e.to_string()))
}

pub fn aes_gcm_decrypt_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm,
    };
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("Invalid key".into()))?;
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("Decryption failed".into()))
}

/// Zincirleme (cascade) AEAD: içte XChaCha20-Poly1305, dışta AES-256-GCM; anahtarlar HKDF ile bağımsız.
/// İki farklı tasarıma (ARX akış şifresi + blok şifre) dayanır: biri kırılsa diğeri gizliliği ve bütünlüğü korur.
/// `nonce` anahtar başına benzersiz olmalıdır (çağıranlar rastgele veya STREAM nonce'u verir).
pub fn cascade_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let mut kx = subkey(key, b"kaotik-v8-xchacha20poly1305")?;
    let mut ka = subkey(key, b"kaotik-v8-aes256gcm")?;
    let inner = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&kx)
        .map_err(|_| Error::Crypto("Invalid key".into()))?
        .encrypt(
            &xnonce(nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(e.to_string()));
    secure_zero(&mut kx);
    let outer = inner.and_then(|i| aes_gcm_encrypt_aad(&ka, nonce, &i, aad));
    secure_zero(&mut ka);
    outer
}

pub fn cascade_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let mut ka = subkey(key, b"kaotik-v8-aes256gcm")?;
    let inner = aes_gcm_decrypt_aad(&ka, nonce, ciphertext, aad);
    secure_zero(&mut ka);
    let inner = zeroize::Zeroizing::new(inner?);
    let mut kx = subkey(key, b"kaotik-v8-xchacha20poly1305")?;
    let pt = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&kx)
        .map_err(|_| Error::Crypto("Invalid key".into()))?
        .decrypt(&xnonce(nonce).into(), Payload { msg: &inner, aad })
        .map_err(|_| Error::Crypto("Decryption failed".into()));
    secure_zero(&mut kx);
    pt
}

/// Cascade ek yükü: iki etiket.
pub const CASCADE_OVERHEAD: usize = 2 * TAG_LEN;

fn xnonce(nonce: &[u8; NONCE_LEN]) -> [u8; 24] {
    let mut x = [0u8; 24];
    x[..8].copy_from_slice(b"KAOTIKv8");
    x[8..20].copy_from_slice(nonce);
    x
}

/// Seçilen sürüme göre AEAD: v8+ cascade, öncesi yalnız AES-256-GCM.
pub fn seal(
    cascade: bool,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    pt: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if cascade {
        cascade_encrypt(key, nonce, pt, aad)
    } else {
        aes_gcm_encrypt_aad(key, nonce, pt, aad)
    }
}

pub fn open(
    cascade: bool,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if cascade {
        cascade_decrypt(key, nonce, ct, aad)
    } else {
        aes_gcm_decrypt_aad(key, nonce, ct, aad)
    }
}

/// STREAM yapısı (Hoang-Reyhanitabar-Rogaway-Vizár): prefix(7) || sayaç(4, BE) || son_blok(1).
/// Son blok bayrağı sayesinde kesme (truncation) ve blok yer değiştirme saldırıları tespit edilir.
pub fn stream_nonce(prefix: &[u8; 7], counter: u32, last: bool) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    n
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cascade_roundtrip_and_each_layer_authenticates() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let ct = cascade_encrypt(&key, &nonce, b"secret", b"aad").unwrap();
        assert_eq!(ct.len(), 6 + CASCADE_OVERHEAD);
        assert_eq!(
            cascade_decrypt(&key, &nonce, &ct, b"aad").unwrap(),
            b"secret"
        );
        assert!(cascade_decrypt(&key, &nonce, &ct, b"aaX").is_err());
        assert!(cascade_decrypt(&[8u8; KEY_LEN], &nonce, &ct, b"aad").is_err());
        // Dış AES katmanı soyulsa bile iç XChaCha katmanı ayrı anahtarla şifreli kalır.
        let ka = subkey(&key, b"kaotik-v8-aes256gcm").unwrap();
        let inner = aes_gcm_decrypt_aad(&ka, &nonce, &ct, b"aad").unwrap();
        assert!(!inner.windows(6).any(|w| w == b"secret"));
    }
}
