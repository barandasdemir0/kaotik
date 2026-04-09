//! # Kaotik — platform-bağımsız şifreleme kütüphanesi
//!
//! Modlar: **kaotik** (parola + kaotik katman + AES), **aes** (sadece AES-256-GCM, streaming),
//! **kyber** (NIST ML-KEM Kyber-768 + parola ile korunan anahtar dosyası).

pub mod chaotic;
pub mod crypto;
pub mod error;
pub mod format;
pub mod nist_kyber;
pub mod password;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use error::{Error, Result};
pub use password::validate_password;
pub use format::{
    read_header, read_encrypted_secret_key, read_aes_chunked_start, write_header,
    write_encrypted_secret_key, write_aes_chunked_start,
    write_kyber_payload, read_kyber_payload,
    FORMAT_AES, FORMAT_KAOTIK, FORMAT_KYBER,
    VERSION_AES_CHUNKED, VERSION_CURRENT, VERSION_LEGACY,
};

use std::io::{Read, Write};

/// AES streaming: blok boyutu (64 KiB); büyük dosyalar bellekte tutulmaz.
const AES_CHUNK_SIZE: usize = 64 * 1024;
/// Chunk boyutu üst sınırı; bozuk/zararlı dosyada bellek taşması önlenir.
const MAX_AES_CHUNK_SIZE: usize = 16 * 1024 * 1024;
/// Kaotik mod maksimum plaintext boyutu (256 MiB). Daha büyük dosyalar için AES modu kullanın.
const MAX_KAOTIK_SIZE: usize = 256 * 1024 * 1024;

/// Kaotik mod: parola + 8 katman kaotik (XOR, permütasyon, S-box) + AES-256-GCM. Tek seferde belleğe alır; büyük dosya için AES modu kullanın.
pub fn encrypt_kaotik<R: Read, W: Write>(mut reader: R, mut writer: W, password: &str) -> Result<()> {
    validate_password(password)?;
    let salt = crypto::gen_salt()?;
    let nonce = crypto::gen_nonce()?;
    let kdf = crypto::KDF_ARGON2;
    let mut key = crypto::derive_key(password, &salt, kdf)?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    if plaintext.len() > MAX_KAOTIK_SIZE {
        crypto::secure_zero(&mut key);
        return Err(Error::Format(format!(
            "Kaotik mode: input too large ({} bytes, max {} bytes). Use --mode aes for large files.",
            plaintext.len(), MAX_KAOTIK_SIZE
        )));
    }
    chaotic::apply_chaotic_xor_layers(&mut plaintext, password, &salt)?;
    let ciphertext_with_tag = crypto::aes_gcm_encrypt(&key, &nonce, &plaintext)?;
    crypto::secure_zero(plaintext.as_mut_slice());
    format::write_header(&mut writer, format::VERSION_CURRENT, format::FORMAT_KAOTIK)?;
    format::write_kaotik_payload(&mut writer, &salt, kdf, &nonce, &ciphertext_with_tag)?;
    crypto::secure_zero(&mut key);
    Ok(())
}

/// Kaotik mod dosyasını parola ile çözer.
pub fn decrypt_kaotik<R: Read, W: Write>(mut reader: R, mut writer: W, password: &str) -> Result<()> {
    validate_password(password)?;
    let (version, format_byte) = format::read_header(&mut reader)?;
    if format_byte != format::FORMAT_KAOTIK {
        return Err(Error::Format("Not a Kaotik format file".into()));
    }
    let (salt, kdf, nonce, ciphertext_with_tag) = format::read_kaotik_payload(&mut reader, version)?;
    if ciphertext_with_tag.len() > MAX_KAOTIK_SIZE + 32 {
        return Err(Error::Format("Kaotik ciphertext too large".into()));
    }
    let mut key = crypto::derive_key(password, &salt, kdf)?;
    let mut plaintext = crypto::aes_gcm_decrypt(&key, &nonce, &ciphertext_with_tag)?;
    chaotic::reverse_chaotic_xor_layers(&mut plaintext, password, &salt)?;
    writer.write_all(&plaintext)?;
    crypto::secure_zero(plaintext.as_mut_slice());
    crypto::secure_zero(&mut key);
    Ok(())
}

/// Kyber mod: NIST ML-KEM Kyber-768. Paylaşılan gizlilik AES anahtarı olur; gizli anahtar `secret_key_out`'a parola ile şifrelenmiş yazılır.
pub fn encrypt_kyber<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
    secret_key_out: &mut dyn Write,
) -> Result<()> {
    validate_password(password)?;
    let mut kp = nist_kyber::generate_keypair()?;
    let (mut ss, kem_ct) = nist_kyber::encapsulate(&kp.public_key)?;
    if ss.len() < 32 {
        crypto::secure_zero(ss.as_mut_slice());
        return Err(Error::Crypto("Kyber shared secret too short".into()));
    }
    let mut aes_key: [u8; 32] = ss[..32]
        .try_into()
        .map_err(|_| Error::Crypto("Kyber shared secret too short".into()))?;
    let nonce = crypto::gen_nonce()?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    let ciphertext_with_tag = crypto::aes_gcm_encrypt(&aes_key, &nonce, &plaintext)?;
    crypto::secure_zero(plaintext.as_mut_slice());
    format::write_header(&mut writer, format::VERSION_LEGACY, format::FORMAT_KYBER)?;
    format::write_kyber_payload(&mut writer, &kem_ct, &nonce, &ciphertext_with_tag)?;
    let key_salt = crypto::gen_salt()?;
    let key_nonce = crypto::gen_nonce()?;
    let kdf = crypto::KDF_ARGON2;
    let mut key_file_key = crypto::derive_key(password, &key_salt, kdf)?;
    let encrypted_sk = crypto::aes_gcm_encrypt(&key_file_key, &key_nonce, &kp.secret_key)?;
    format::write_encrypted_secret_key(secret_key_out, 3, &key_salt, kdf, &key_nonce, &encrypted_sk)?;
    crypto::secure_zero(ss.as_mut_slice());
    crypto::secure_zero(&mut aes_key);
    crypto::secure_zero(kp.secret_key.as_mut_slice());
    crypto::secure_zero(&mut key_file_key);
    Ok(())
}

/// AES modu: sadece AES-256-GCM, 64 KiB chunk (streaming). Büyük dosyalar bellekte tutulmaz.
pub fn encrypt_aes<R: Read, W: Write>(mut reader: R, mut writer: W, password: &str) -> Result<()> {
    validate_password(password)?;
    let salt = crypto::gen_salt()?;
    let base_nonce = crypto::gen_nonce()?;
    let kdf = crypto::KDF_ARGON2;
    let mut key = crypto::derive_key(password, &salt, kdf)?;
    format::write_header(&mut writer, format::VERSION_AES_CHUNKED, format::FORMAT_AES)?;
    format::write_aes_chunked_start(&mut writer, &salt, kdf, &base_nonce)?;
    let mut chunk_index: u32 = 0;
    let mut buf = vec![0u8; AES_CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let nonce = crypto::nonce_for_chunk(&base_nonce, chunk_index);
        let ct = crypto::aes_gcm_encrypt(&key, &nonce, &buf[..n])?;
        writer.write_all(&(ct.len() as u32).to_le_bytes())?;
        writer.write_all(&ct)?;
        chunk_index = chunk_index.saturating_add(1);
        if chunk_index == u32::MAX {
            crypto::secure_zero(&mut key);
            return Err(Error::Format("Too many chunks".into()));
        }
    }
    writer.write_all(&0u32.to_le_bytes())?;
    crypto::secure_zero(&mut key);
    Ok(())
}

/// AES modu dosyasını çözer. v4 (chunked) ve v3 (tek blok) format desteklenir.
pub fn decrypt_aes<R: Read, W: Write>(mut reader: R, mut writer: W, password: &str) -> Result<()> {
    validate_password(password)?;
    let (version, format_byte) = format::read_header(&mut reader)?;
    if format_byte != format::FORMAT_AES {
        return Err(Error::Format("Not an AES format file".into()));
    }
    if version >= format::VERSION_AES_CHUNKED {
        let (salt, kdf, base_nonce) = format::read_aes_chunked_start(&mut reader)?;
        let mut key = crypto::derive_key(password, &salt, kdf)?;
        let mut chunk_index: u32 = 0;
        loop {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 {
                break;
            }
            if len > MAX_AES_CHUNK_SIZE {
                crypto::secure_zero(&mut key);
                return Err(Error::Format("Chunk size exceeds limit".into()));
            }
            let mut ct = vec![0u8; len];
            reader.read_exact(&mut ct)?;
            let nonce = crypto::nonce_for_chunk(&base_nonce, chunk_index);
            let pt = crypto::aes_gcm_decrypt(&key, &nonce, &ct)?;
            writer.write_all(&pt)?;
            chunk_index = chunk_index.saturating_add(1);
            if chunk_index == u32::MAX {
                crypto::secure_zero(&mut key);
                return Err(Error::Format("Too many chunks".into()));
            }
        }
        crypto::secure_zero(&mut key);
    } else {
        let (salt, kdf, nonce, ciphertext_with_tag) = format::read_kaotik_payload(&mut reader, version)?;
        let mut key = crypto::derive_key(password, &salt, kdf)?;
        let mut plaintext = crypto::aes_gcm_decrypt(&key, &nonce, &ciphertext_with_tag)?;
        writer.write_all(&plaintext)?;
        crypto::secure_zero(plaintext.as_mut_slice());
        crypto::secure_zero(&mut key);
    }
    Ok(())
}

/// Kyber mod dosyasını çözer. Gizli anahtar `key_file_reader`'dan parola ile açılır; KEM decapsulate sonrası AES ile çözülür.
pub fn decrypt_kyber<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
    key_file_reader: &mut dyn Read,
) -> Result<()> {
    validate_password(password)?;
    let (_key_ver, key_salt, key_kdf, key_nonce, encrypted_sk) = format::read_encrypted_secret_key(key_file_reader)?;
    let mut key_file_key = crypto::derive_key(password, &key_salt, key_kdf)?;
    let mut sk_bytes = crypto::aes_gcm_decrypt(&key_file_key, &key_nonce, &encrypted_sk)?;
    crypto::secure_zero(&mut key_file_key);
    let (_version, format_byte) = format::read_header(&mut reader)?;
    if format_byte != format::FORMAT_KYBER {
        crypto::secure_zero(sk_bytes.as_mut_slice());
        return Err(Error::Format("Not a Kyber format file".into()));
    }
    let (kem_ct, nonce, ciphertext_with_tag) = format::read_kyber_payload(&mut reader)?;
    let mut ss = nist_kyber::decapsulate(&kem_ct, &sk_bytes)?;
    crypto::secure_zero(sk_bytes.as_mut_slice());
    if ss.len() < 32 {
        crypto::secure_zero(ss.as_mut_slice());
        return Err(Error::Crypto("Decryption failed".into()));
    }
    let mut aes_key: [u8; 32] = ss[..32]
        .try_into()
        .map_err(|_| Error::Crypto("Decryption failed".into()))?;
    let mut plaintext = crypto::aes_gcm_decrypt(&aes_key, &nonce, &ciphertext_with_tag)?;
    writer.write_all(&plaintext)?;
    crypto::secure_zero(plaintext.as_mut_slice());
    crypto::secure_zero(ss.as_mut_slice());
    crypto::secure_zero(&mut aes_key);
    Ok(())
}

/// Dosya yapısını doğrular (header + payload öneki). Parola veya içeriği çözmez.
pub fn verify_file<R: Read>(mut reader: R) -> Result<()> {
    let (version, format_byte) = format::read_header(&mut reader)?;
    match format_byte {
        format::FORMAT_KAOTIK => {
            let mut salt = [0u8; format::SALT_LEN];
            reader.read_exact(&mut salt)?;
            if version >= format::VERSION_CURRENT {
                let mut kdf = [0u8; 1];
                reader.read_exact(&mut kdf)?;
            }
            let mut nonce = [0u8; format::NONCE_LEN];
            reader.read_exact(&mut nonce)?;
        }
        format::FORMAT_AES => {
            if version >= format::VERSION_AES_CHUNKED {
                let _ = format::read_aes_chunked_start(&mut reader)?;
                loop {
                    let mut len_buf = [0u8; 4];
                    reader.read_exact(&mut len_buf)?;
                    let len = u32::from_le_bytes(len_buf) as usize;
                    if len == 0 {
                        break;
                    }
                    if len > MAX_AES_CHUNK_SIZE {
                        return Err(Error::Format("Chunk size exceeds limit".into()));
                    }
                    let mut skip = vec![0u8; len];
                    reader.read_exact(&mut skip)?;
                }
            } else {
                let mut salt = [0u8; format::SALT_LEN];
                reader.read_exact(&mut salt)?;
                let mut kdf = [0u8; 1];
                reader.read_exact(&mut kdf)?;
                let mut nonce = [0u8; format::NONCE_LEN];
                reader.read_exact(&mut nonce)?;
            }
        }
        format::FORMAT_KYBER => {
            let (_, _, _) = format::read_kyber_payload(&mut reader)?;
        }
        _ => return Err(Error::Format("Unknown format byte".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_PASSWORD: &str = "TestPassword123!@#";

    #[test]
    fn test_password_validation() {
        assert!(validate_password(TEST_PASSWORD).is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password("nouppercase123!@#").is_err());
    }

    #[test]
    fn test_kaotik_roundtrip() {
        let plain = b"Hello, Kaotik encryption!";
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
        assert!(cipher.starts_with(b"KAOS"));
        let mut dec = Vec::new();
        decrypt_kaotik(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap();
        assert_eq!(&dec[..], &plain[..]);
    }

    #[test]
    fn test_kaotik_v2_payload_parse() {
        // v2 payload: salt(32) + nonce(12) + ct (kdf byte yok); read_kaotik_payload(version=2) kdf=0 döner.
        use crate::format::read_kaotik_payload;
        let mut v2_payload = Vec::new();
        v2_payload.extend_from_slice(&[0u8; 32]);
        v2_payload.extend_from_slice(&[0u8; 12]);
        v2_payload.extend_from_slice(b"tail");
        let (s, kdf, n, c) = read_kaotik_payload(&mut std::io::Cursor::new(&v2_payload), 2).unwrap();
        assert_eq!(kdf, 0, "v2 format has no KDF byte, should default to PBKDF2");
        assert_eq!(s.len(), 32);
        assert_eq!(n.len(), 12);
        assert_eq!(&c[..], b"tail");
    }

    #[test]
    fn test_aes_roundtrip() {
        let plain = b"Hello, AES-only mode!";
        let mut cipher = Vec::new();
        encrypt_aes(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
        assert!(cipher.starts_with(b"KAOS"));
        let mut dec = Vec::new();
        decrypt_aes(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap();
        assert_eq!(&dec[..], &plain[..]);
    }

    #[test]
    fn test_aes_streaming_large() {
        let plain: Vec<u8> = (0..70 * 1024).map(|i| (i % 251) as u8).collect();
        let mut cipher = Vec::new();
        encrypt_aes(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
        let mut dec = Vec::new();
        decrypt_aes(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap();
        assert_eq!(dec.len(), plain.len());
        assert_eq!(&dec[..], &plain[..]);
    }

    #[test]
    fn test_kyber_roundtrip() {
        let plain = b"Hello, Kyber mode!";
        let mut cipher = Vec::new();
        let mut key_out = Vec::new();
        encrypt_kyber(
            Cursor::new(&plain[..]),
            &mut cipher,
            TEST_PASSWORD,
            &mut key_out,
        )
        .unwrap();
        assert!(cipher.starts_with(b"KAOS"));
        let mut key_cursor = Cursor::new(key_out);
        let mut dec = Vec::new();
        decrypt_kyber(
            Cursor::new(&cipher),
            &mut dec,
            TEST_PASSWORD,
            &mut key_cursor,
        )
        .unwrap();
        assert_eq!(&dec[..], &plain[..]);
    }

    #[test]
    fn test_wrong_password_fails() {
        let plain = b"secret";
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
        let mut dec = Vec::new();
        let err = decrypt_kaotik(Cursor::new(&cipher), &mut dec, "WrongPassword123!@#").unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn test_kaotik_empty_roundtrip() {
        let plain: &[u8] = &[];
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(plain), &mut cipher, TEST_PASSWORD).unwrap();
        let mut dec = Vec::new();
        decrypt_kaotik(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn test_kaotik_single_byte_roundtrip() {
        let plain: &[u8] = &[0xAB];
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(plain), &mut cipher, TEST_PASSWORD).unwrap();
        let mut dec = Vec::new();
        decrypt_kaotik(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_corrupted_file_fails() {
        let mut dec = Vec::new();
        let bad: &[u8] = b"NOT_KAOS\x00\x00\x00";
        assert!(decrypt_kaotik(Cursor::new(bad), &mut dec, TEST_PASSWORD).is_err());
    }

    #[test]
    fn test_empty_data_roundtrip() {
        let plain: &[u8] = &[];
        let mut cipher = Vec::new();
        encrypt_aes(Cursor::new(plain), &mut cipher, TEST_PASSWORD).unwrap();
        let mut dec = Vec::new();
        decrypt_aes(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    #[ignore] // 257 MiB allocation; run with: cargo test --release test_kaotik_size_limit -- --ignored
    fn test_kaotik_size_limit() {
        let plain = vec![0u8; 256 * 1024 * 1024 + 1];
        let mut cipher = Vec::new();
        let err = encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap_err();
        assert!(matches!(err, Error::Format(_)));
        assert!(plain.len() > MAX_KAOTIK_SIZE);
    }

    #[test]
    fn test_cross_mode_error() {
        let plain = b"kaotik encrypted";
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
        let mut dec = Vec::new();
        let err = decrypt_aes(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap_err();
        assert!(matches!(err, Error::Format(_)));
    }

    #[test]
    fn test_verify_file() {
        let plain = b"verify me";
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
        assert!(verify_file(Cursor::new(&cipher)).is_ok());
        let bad: &[u8] = b"KAOS\x00\x00\x01\x00";
        assert!(verify_file(Cursor::new(bad)).is_err());
    }
}
