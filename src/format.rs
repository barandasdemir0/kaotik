//! Dosya formatı: KAOS magic, sürüm, format byte; kaotik/Kyber/AES payload layout.
use crate::error::{Error, Result};
use std::io::{Read, Write};

pub use crate::crypto::{NONCE_LEN, SALT_LEN};

pub const MAGIC: &[u8; 4] = b"KAOS";
/// Eski format: KDF byte yok, PBKDF2 kullanılır.
pub const VERSION_LEGACY: u16 = 2;
/// Güncel format: Kaotik payload'da KDF byte (Argon2id önerilir).
pub const VERSION_CURRENT: u16 = 3;
/// AES chunked streaming (büyük dosyalar).
pub const VERSION_AES_CHUNKED: u16 = 4;

pub const FORMAT_KAOTIK: u8 = 0x01;
pub const FORMAT_KYBER: u8 = 0x02;
pub const FORMAT_AES: u8 = 0x03;

pub type KaotikPayload = ([u8; SALT_LEN], u8, [u8; NONCE_LEN], Vec<u8>);
pub type EncryptedSecretKeyPayload = (u8, [u8; SALT_LEN], u8, [u8; NONCE_LEN], Vec<u8>);

pub fn write_header<W: Write>(w: &mut W, version: u16, format_byte: u8) -> Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&version.to_le_bytes())?;
    w.write_all(&[format_byte])?;
    Ok(())
}

/// (version, format_byte) döner. Eski dosyalar v2, yeni kaotik/aes v3.
pub fn read_header<R: Read>(r: &mut R) -> Result<(u16, u8)> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::Format("Invalid magic".into()));
    }
    let mut ver = [0u8; 2];
    r.read_exact(&mut ver)?;
    let version = u16::from_le_bytes(ver);
    let mut fmt = [0u8; 1];
    r.read_exact(&mut fmt)?;
    Ok((version, fmt[0]))
}

/// v3: salt(32) + kdf(1) + nonce(12) + ciphertext. v2: salt + nonce + ct (kdf=PBKDF2).
pub fn write_kaotik_payload<W: Write>(
    w: &mut W,
    salt: &[u8; SALT_LEN],
    kdf: u8,
    nonce: &[u8; NONCE_LEN],
    ciphertext_with_tag: &[u8],
) -> Result<()> {
    w.write_all(salt)?;
    w.write_all(&[kdf])?;
    w.write_all(nonce)?;
    w.write_all(ciphertext_with_tag)?;
    Ok(())
}

/// version >= 3 ise kdf byte okunur, yoksa kdf = 0 (PBKDF2).
pub fn read_kaotik_payload<R: Read>(
    r: &mut R,
    version: u16,
) -> Result<KaotikPayload> {
    let mut salt = [0u8; SALT_LEN];
    r.read_exact(&mut salt)?;
    let kdf = if version >= VERSION_CURRENT {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        b[0]
    } else {
        0 // eski format: PBKDF2
    };
    let mut nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut nonce)?;
    let mut ciphertext = Vec::new();
    r.read_to_end(&mut ciphertext)?;
    Ok((salt, kdf, nonce, ciphertext))
}

// NIST Kyber-768: ct (değişken) + nonce (12) + aes_gcm_ciphertext
pub fn write_kyber_payload<W: Write>(
    w: &mut W,
    kem_ct: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext_with_tag: &[u8],
) -> Result<()> {
    w.write_all(&(kem_ct.len() as u32).to_le_bytes())?;
    w.write_all(kem_ct)?;
    w.write_all(nonce)?;
    w.write_all(ciphertext_with_tag)?;
    Ok(())
}

/// Kyber-768 KEM ciphertext sabit 1088 byte; üst sınır sahtecilik/DoS önlemi.
const MAX_KEM_CT_LEN: usize = 2048;

pub fn read_kyber_payload<R: Read>(
    r: &mut R,
) -> Result<(Vec<u8>, [u8; NONCE_LEN], Vec<u8>)> {
    let mut ct_len_buf = [0u8; 4];
    r.read_exact(&mut ct_len_buf)?;
    let ct_len = u32::from_le_bytes(ct_len_buf) as usize;
    if ct_len > MAX_KEM_CT_LEN {
        return Err(Error::Format("Invalid Kyber ciphertext length".into()));
    }
    let mut kem_ct = vec![0u8; ct_len];
    r.read_exact(&mut kem_ct)?;
    let mut nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut nonce)?;
    let mut ciphertext = Vec::new();
    r.read_to_end(&mut ciphertext)?;
    Ok((kem_ct, nonce, ciphertext))
}

/// AES chunked: salt(32) + kdf(1) + base_nonce(12); sonra her blok için len(4 LE) + ciphertext.
pub fn write_aes_chunked_start<W: Write>(
    w: &mut W,
    salt: &[u8; SALT_LEN],
    kdf: u8,
    base_nonce: &[u8; NONCE_LEN],
) -> Result<()> {
    w.write_all(salt)?;
    w.write_all(&[kdf])?;
    w.write_all(base_nonce)?;
    Ok(())
}

pub fn read_aes_chunked_start<R: Read>(
    r: &mut R,
) -> Result<([u8; SALT_LEN], u8, [u8; NONCE_LEN])> {
    let mut salt = [0u8; SALT_LEN];
    r.read_exact(&mut salt)?;
    let mut kdf = [0u8; 1];
    r.read_exact(&mut kdf)?;
    let mut base_nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut base_nonce)?;
    Ok((salt, kdf[0], base_nonce))
}

/// Gizli anahtar dosyası. v2: salt(32)+nonce(12)+ct. v3: version(1)=3 + salt(32)+kdf(1)+nonce(12)+ct.
pub fn write_encrypted_secret_key<W: Write + ?Sized>(
    w: &mut W,
    version: u8,
    salt: &[u8; SALT_LEN],
    kdf: u8,
    nonce: &[u8; NONCE_LEN],
    encrypted_sk: &[u8],
) -> Result<()> {
    if version >= 3 {
        w.write_all(&[3u8])?;
        w.write_all(salt)?;
        w.write_all(&[kdf])?;
        w.write_all(nonce)?;
    } else {
        w.write_all(salt)?;
        w.write_all(nonce)?;
    }
    w.write_all(encrypted_sk)?;
    Ok(())
}

/// version_byte: 3 = yeni (salt,kdf,nonce,ct), değilse eski (ilk okunan byte tuzun parçası: salt 31 okumak gerekir).
pub fn read_encrypted_secret_key<R: Read + ?Sized>(
    r: &mut R,
) -> Result<EncryptedSecretKeyPayload> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first)?;
    let version = first[0];
    if version == 3 {
        let mut salt = [0u8; SALT_LEN];
        r.read_exact(&mut salt)?;
        let mut kdf = [0u8; 1];
        r.read_exact(&mut kdf)?;
        let mut nonce = [0u8; NONCE_LEN];
        r.read_exact(&mut nonce)?;
        let mut encrypted = Vec::new();
        r.read_to_end(&mut encrypted)?;
        return Ok((3, salt, kdf[0], nonce, encrypted));
    }
    // Eski format: first byte tuzun ilk byte'ı; 31 tuz, 12 nonce, kalan ct
    let mut salt = [0u8; SALT_LEN];
    salt[0] = first[0];
    r.read_exact(&mut salt[1..])?;
    let mut nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut nonce)?;
    let mut encrypted = Vec::new();
    r.read_to_end(&mut encrypted)?;
    Ok((2, salt, 0, nonce, encrypted))
}
