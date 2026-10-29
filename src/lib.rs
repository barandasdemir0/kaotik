//! # Kaotik — platform-bağımsız şifreleme kütüphanesi
//!
//! Modlar: **kaotik** (parola + kaotik katman + AES), **aes** (sadece AES-256-GCM, streaming),
//! **kyber** (NIST ML-KEM Kyber-768 + parola ile korunan anahtar dosyası).

pub mod chaotic;
pub mod crypto;
pub mod error;
pub mod format;
pub mod hybrid_kem;
pub mod nist_kyber;
pub mod password;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use error::{Error, Result};
pub use format::{
    read_aes_chunked_start, read_encrypted_secret_key, read_header, read_kyber_payload,
    write_aes_chunked_start, write_encrypted_secret_key, write_header, write_kyber_payload,
    FORMAT_AES, FORMAT_KAOTIK, FORMAT_KYBER, VERSION_AEAD_BOUND, VERSION_AES_CHUNKED,
    VERSION_CURRENT, VERSION_KAOTIK_PADDED, VERSION_LEGACY,
};
pub use password::{generate_passphrase, validate_password};

use std::io::{Read, Write};
use zeroize::Zeroizing;

/// AES streaming: blok boyutu (64 KiB); büyük dosyalar bellekte tutulmaz.
const AES_CHUNK_SIZE: usize = 64 * 1024;
/// Chunk boyutu üst sınırı; bozuk/zararlı dosyada bellek taşması önlenir.
const MAX_AES_CHUNK_SIZE: usize = 16 * 1024 * 1024;
/// Kaotik mod maksimum plaintext boyutu (256 MiB). Daha büyük dosyalar için AES modu kullanın.
const MAX_KAOTIK_SIZE: usize = 256 * 1024 * 1024;
/// Kaotik boyut gizleme için dolgu hedef bloğu.
const KAOTIK_PAD_BLOCK: usize = 256;
/// Ek rastgele dolgu blok üst sınırı.
const KAOTIK_PAD_EXTRA_MAX_BLOCKS: usize = 8;
/// Kaotik dolgu üst sınırı: len-prefix + hizalama + ekstra bloklar.
const MAX_KAOTIK_PADDING_OVERHEAD: usize =
    8 + (KAOTIK_PAD_BLOCK - 1) + KAOTIK_PAD_EXTRA_MAX_BLOCKS * KAOTIK_PAD_BLOCK;

fn apply_random_padding(plain: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut chooser = [0u8; 1];
    crypto::random_bytes(&mut chooser)?;
    let extra_blocks = (chooser[0] as usize) % (KAOTIK_PAD_EXTRA_MAX_BLOCKS + 1);

    let base_len = 8 + plain.len();
    let aligned = base_len.div_ceil(KAOTIK_PAD_BLOCK) * KAOTIK_PAD_BLOCK;
    let target_len = aligned + (extra_blocks * KAOTIK_PAD_BLOCK);
    let pad_len = target_len.saturating_sub(base_len);

    let mut out = Zeroizing::new(Vec::with_capacity(target_len));
    out.extend_from_slice(&(plain.len() as u64).to_le_bytes());
    out.extend_from_slice(plain);
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        crypto::random_bytes(&mut pad)?;
        out.extend_from_slice(&pad);
        crypto::secure_zero(&mut pad);
    }
    Ok(out)
}

fn remove_random_padding(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 8 {
        return Err(Error::Crypto("Decryption failed".into()));
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&padded[..8]);
    let real_len = u64::from_le_bytes(len_bytes) as usize;
    let payload = &padded[8..];
    if real_len > payload.len() {
        return Err(Error::Crypto("Decryption failed".into()));
    }
    Ok(payload[..real_len].to_vec())
}

/// v6 kaotik anahtarları: AEAD anahtarı ve kaotik katman anahtarı aynı Argon2id ana anahtarından HKDF ile ayrılır.
fn kaotik_v6_keys(
    master: &[u8; crypto::KEY_LEN],
) -> Result<([u8; crypto::KEY_LEN], Zeroizing<String>)> {
    let aead_key = crypto::subkey(master, b"kaotik-v6-aead")?;
    let mut chaos = crypto::subkey(master, b"kaotik-v6-chaos")?;
    let mut s = Zeroizing::new(String::with_capacity(64));
    for b in chaos.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    crypto::secure_zero(&mut chaos);
    Ok((aead_key, s))
}

/// Okuyucudan tamponu doldurur (kısa okumaları birleştirir). Okunan bayt sayısını döner.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

/// Kaotik mod: parola + 8 katman kaotik (XOR, permütasyon, S-box) + AES-256-GCM. Tek seferde belleğe alır; büyük dosya için AES modu kullanın.
/// v6: Argon2id (256 MiB) ana anahtar → HKDF alt anahtarları; başlık ve metaveri AAD ile doğrulanır.
pub fn encrypt_kaotik<R: Read, W: Write>(reader: R, mut writer: W, password: &str) -> Result<()> {
    validate_password(password)?;
    let salt = crypto::gen_salt()?;
    let nonce = crypto::gen_nonce()?;
    let kdf = crypto::KDF_DEFAULT;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .take(MAX_KAOTIK_SIZE as u64 + 1)
        .read_to_end(&mut plaintext)?;
    if plaintext.len() > MAX_KAOTIK_SIZE {
        return Err(Error::Format(format!(
            "Kaotik mode: input too large ({} bytes, max {} bytes). Use --mode aes for large files.",
            plaintext.len(), MAX_KAOTIK_SIZE
        )));
    }
    let mut master = crypto::derive_key(password, &salt, kdf)?;
    let (mut key, chaos_key) = kaotik_v6_keys(&master)?;
    crypto::secure_zero(&mut master);
    let mut padded = apply_random_padding(&plaintext)?;
    chaotic::apply_chaotic_xor_layers(&mut padded, &chaos_key, &salt)?;
    let header = format::header_bytes(format::VERSION_AEAD_BOUND, format::FORMAT_KAOTIK);
    let aad = [&header[..], &salt[..], &[kdf], &nonce[..]].concat();
    let ciphertext_with_tag = crypto::aes_gcm_encrypt_aad(&key, &nonce, &padded, &aad)?;
    crypto::secure_zero(plaintext.as_mut_slice());
    crypto::secure_zero(&mut key);
    writer.write_all(&header)?;
    format::write_kaotik_payload(&mut writer, &salt, kdf, &nonce, &ciphertext_with_tag)?;
    Ok(())
}

/// Kaotik mod dosyasını parola ile çözer (v2–v6).
pub fn decrypt_kaotik<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
) -> Result<()> {
    let result = (|| {
        validate_password(password)?;
        let (version, format_byte) = format::read_header(&mut reader)?;
        if format_byte != format::FORMAT_KAOTIK {
            return Err(Error::Format("Not a Kaotik format file".into()));
        }
        let max_ct = MAX_KAOTIK_SIZE + MAX_KAOTIK_PADDING_OVERHEAD + 32;
        let (salt, kdf, nonce, ciphertext_with_tag) =
            format::read_kaotik_payload(&mut (&mut reader).take(max_ct as u64 + 1 + 64), version)?;
        if ciphertext_with_tag.len() > max_ct {
            return Err(Error::Format("Kaotik ciphertext too large".into()));
        }
        let mut master = crypto::derive_key(password, &salt, kdf)?;
        let mut padded_plain = if version >= format::VERSION_AEAD_BOUND {
            let (mut key, chaos_key) = kaotik_v6_keys(&master)?;
            crypto::secure_zero(&mut master);
            let header = format::header_bytes(version, format_byte);
            let aad = [&header[..], &salt[..], &[kdf], &nonce[..]].concat();
            let dec = crypto::aes_gcm_decrypt_aad(&key, &nonce, &ciphertext_with_tag, &aad);
            crypto::secure_zero(&mut key);
            let mut p = Zeroizing::new(dec?);
            chaotic::reverse_chaotic_xor_layers(&mut p, &chaos_key, &salt)?;
            p
        } else {
            let dec = crypto::aes_gcm_decrypt(&master, &nonce, &ciphertext_with_tag);
            crypto::secure_zero(&mut master);
            let mut p = Zeroizing::new(dec?);
            chaotic::reverse_chaotic_xor_layers(&mut p, password, &salt)?;
            p
        };
        let mut final_plain = if version >= format::VERSION_KAOTIK_PADDED {
            Zeroizing::new(remove_random_padding(&padded_plain)?)
        } else {
            Zeroizing::new(padded_plain.to_vec())
        };
        writer.write_all(&final_plain)?;
        crypto::secure_zero(final_plain.as_mut_slice());
        crypto::secure_zero(padded_plain.as_mut_slice());
        Ok(())
    })();
    result
}

/// Kyber hibrit anahtar: HKDF(KEM paylaşılan sırrı || Argon2id(parola)). Saldırgan dosyayı açmak için
/// hem Kyber gizli anahtarını kırmalı/ele geçirmeli hem de parolayı bulmalıdır (biri kırılsa diğeri korur).
fn kyber_hybrid_key(
    ss: &[u8],
    pw_key: &[u8; crypto::KEY_LEN],
    salt: &[u8],
    kem_ct: &[u8],
) -> Result<[u8; crypto::KEY_LEN]> {
    use sha2::{Digest, Sha256};
    let ct_hash = Sha256::digest(kem_ct);
    let ikm = Zeroizing::new([ss, &pw_key[..]].concat());
    let info = [&b"kaotik-v6-kyber-hybrid"[..], &ct_hash[..]].concat();
    let okm = Zeroizing::new(crypto::hkdf_expand(
        &ikm,
        &info,
        crypto::KEY_LEN,
        Some(salt),
    )?);
    let mut k = [0u8; crypto::KEY_LEN];
    k.copy_from_slice(&okm);
    Ok(k)
}

/// Kyber mod: NIST Kyber-768 + parola hibrit. Gizli anahtar `secret_key_out`'a parola ile şifrelenmiş yazılır.
/// Anahtar dosyasını şifreli dosyadan AYRI saklayın: ikisi ayrı faktördür.
pub fn encrypt_kyber<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
    secret_key_out: &mut dyn Write,
) -> Result<()> {
    validate_password(password)?;
    let (sk_seed, pk) = hybrid_kem::generate_keypair()?;
    let (kem_ct, ss) = hybrid_kem::encapsulate(&pk)?;
    let salt = crypto::gen_salt()?;
    let kdf = crypto::KDF_DEFAULT;
    let mut pw_key = crypto::derive_key(password, &salt, kdf)?;
    let mut aes_key = kyber_hybrid_key(&ss[..], &pw_key, &salt, &kem_ct)?;
    crypto::secure_zero(&mut pw_key);
    let nonce = crypto::gen_nonce()?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext)?;
    let header = format::header_bytes(format::VERSION_PQ_HYBRID, format::FORMAT_KYBER);
    let aad = [
        &header[..],
        &(kem_ct.len() as u32).to_le_bytes(),
        &kem_ct,
        &salt[..],
        &[kdf],
        &nonce[..],
    ]
    .concat();
    let ciphertext_with_tag = crypto::aes_gcm_encrypt_aad(&aes_key, &nonce, &plaintext, &aad)?;
    crypto::secure_zero(plaintext.as_mut_slice());
    crypto::secure_zero(&mut aes_key);
    writer.write_all(&header)?;
    format::write_kyber_payload_v6(
        &mut writer,
        &kem_ct,
        &salt,
        kdf,
        &nonce,
        &ciphertext_with_tag,
    )?;
    let key_salt = crypto::gen_salt()?;
    let key_nonce = crypto::gen_nonce()?;
    let mut key_file_key = crypto::derive_key(password, &key_salt, kdf)?;
    let encrypted_sk = crypto::aes_gcm_encrypt(&key_file_key, &key_nonce, &sk_seed[..])?;
    crypto::secure_zero(&mut key_file_key);
    format::write_encrypted_secret_key(
        secret_key_out,
        3,
        &key_salt,
        kdf,
        &key_nonce,
        &encrypted_sk,
    )?;
    Ok(())
}

/// STREAM şifreleme: 64 KiB bloklar, her blok sayaç + son-blok bayrağı içeren nonce ile.
fn stream_encrypt<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &[u8; crypto::KEY_LEN],
    prefix: &[u8; 7],
    aad: &[u8],
) -> Result<()> {
    let mut cur = Zeroizing::new(vec![0u8; AES_CHUNK_SIZE]);
    let mut next = Zeroizing::new(vec![0u8; AES_CHUNK_SIZE]);
    let mut cur_len = read_full(reader, &mut cur)?;
    let mut counter: u32 = 0;
    loop {
        let next_len = if cur_len == AES_CHUNK_SIZE {
            read_full(reader, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        let nonce = crypto::stream_nonce(prefix, counter, last);
        let ct = crypto::aes_gcm_encrypt_aad(key, &nonce, &cur[..cur_len], aad)?;
        writer.write_all(&[last as u8])?;
        writer.write_all(&(ct.len() as u32).to_le_bytes())?;
        writer.write_all(&ct)?;
        if last {
            return Ok(());
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::Format("Too many chunks".into()))?;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
}

/// STREAM çözme: kesme, sıra değiştirme ve sona eklenen veri reddedilir.
fn stream_decrypt<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &[u8; crypto::KEY_LEN],
    prefix: &[u8; 7],
    aad: &[u8],
) -> Result<()> {
    let mut counter: u32 = 0;
    loop {
        let mut frame = [0u8; 5];
        reader
            .read_exact(&mut frame)
            .map_err(|_| Error::Crypto("Decryption failed: stream truncated".into()))?;
        let last = match frame[0] {
            0 => false,
            1 => true,
            _ => return Err(Error::Crypto("Decryption failed".into())),
        };
        let len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        if len > AES_CHUNK_SIZE + crypto::TAG_LEN {
            return Err(Error::Format("Chunk size exceeds limit".into()));
        }
        let mut ct = vec![0u8; len];
        reader
            .read_exact(&mut ct)
            .map_err(|_| Error::Crypto("Decryption failed: stream truncated".into()))?;
        let nonce = crypto::stream_nonce(prefix, counter, last);
        let pt = Zeroizing::new(crypto::aes_gcm_decrypt_aad(key, &nonce, &ct, aad)?);
        writer.write_all(&pt)?;
        if last {
            let mut extra = [0u8; 1];
            if reader.read(&mut extra)? != 0 {
                return Err(Error::Crypto("Decryption failed: trailing data".into()));
            }
            return Ok(());
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::Format("Too many chunks".into()))?;
    }
}

/// AES modu: AES-256-GCM STREAM, 64 KiB bloklar. Her blok sayaç + son-blok bayrağı içeren nonce ile şifrelenir;
/// başlık AAD'ye bağlıdır. Kesme, yeniden sıralama ve blok değiştirme tespit edilir.
pub fn encrypt_aes<R: Read, W: Write>(mut reader: R, mut writer: W, password: &str) -> Result<()> {
    validate_password(password)?;
    let salt = crypto::gen_salt()?;
    let mut prefix = [0u8; 7];
    crypto::random_bytes(&mut prefix)?;
    let kdf = crypto::KDF_DEFAULT;
    let mut master = crypto::derive_key(password, &salt, kdf)?;
    let mut key = crypto::subkey(&master, b"kaotik-v6-aes-stream")?;
    crypto::secure_zero(&mut master);
    let header = format::header_bytes(format::VERSION_AEAD_BOUND, format::FORMAT_AES);
    let aad = [&header[..], &salt[..], &[kdf], &prefix[..]].concat();
    writer.write_all(&header)?;
    format::write_aes_stream_start(&mut writer, &salt, kdf, &prefix)?;

    let result = stream_encrypt(&mut reader, &mut writer, &key, &prefix, &aad);
    crypto::secure_zero(&mut key);
    result
}

/// AES modu dosyasını çözer. v6 (STREAM), v4 (chunked) ve v3 (tek blok) desteklenir.
/// Not: akış modunda doğrulanmış bloklar sırayla yazılır; bozulma tespit edilirse hata döner ve çıktı eksik kabul edilmelidir.
pub fn decrypt_aes<R: Read, W: Write>(mut reader: R, mut writer: W, password: &str) -> Result<()> {
    let result = (|| {
        validate_password(password)?;
        let (version, format_byte) = format::read_header(&mut reader)?;
        if format_byte != format::FORMAT_AES {
            return Err(Error::Format("Not an AES format file".into()));
        }
        if version >= format::VERSION_AEAD_BOUND {
            let (salt, kdf, prefix) = format::read_aes_stream_start(&mut reader)?;
            let mut master = crypto::derive_key(password, &salt, kdf)?;
            let mut key = crypto::subkey(&master, b"kaotik-v6-aes-stream")?;
            crypto::secure_zero(&mut master);
            let header = format::header_bytes(version, format_byte);
            let aad = [&header[..], &salt[..], &[kdf], &prefix[..]].concat();
            let r = stream_decrypt(&mut reader, &mut writer, &key, &prefix, &aad);
            crypto::secure_zero(&mut key);
            r?;
        } else if version >= format::VERSION_AES_CHUNKED {
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
            let (salt, kdf, nonce, ciphertext_with_tag) =
                format::read_kaotik_payload(&mut reader, version)?;
            let mut key = crypto::derive_key(password, &salt, kdf)?;
            let mut plaintext =
                Zeroizing::new(crypto::aes_gcm_decrypt(&key, &nonce, &ciphertext_with_tag)?);
            writer.write_all(&plaintext)?;
            crypto::secure_zero(plaintext.as_mut_slice());
            crypto::secure_zero(&mut key);
        }
        Ok(())
    })();
    result
}

/// Kyber mod dosyasını çözer. Gizli anahtar `key_file_reader`'dan parola ile açılır; KEM decapsulate sonrası AES ile çözülür.
pub fn decrypt_kyber<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
    key_file_reader: &mut dyn Read,
) -> Result<()> {
    let result = (|| {
        validate_password(password)?;
        let (_key_ver, key_salt, key_kdf, key_nonce, encrypted_sk) =
            format::read_encrypted_secret_key(key_file_reader)?;
        let mut key_file_key = crypto::derive_key(password, &key_salt, key_kdf)?;
        let sk = crypto::aes_gcm_decrypt(&key_file_key, &key_nonce, &encrypted_sk);
        crypto::secure_zero(&mut key_file_key);
        let sk_bytes = Zeroizing::new(sk?);
        let (version, format_byte) = format::read_header(&mut reader)?;
        if format_byte != format::FORMAT_KYBER {
            return Err(Error::Format("Not a Kyber format file".into()));
        }
        let mut aes_key: [u8; 32];
        let (nonce, ciphertext_with_tag, aad) = if version >= format::VERSION_AEAD_BOUND {
            let (kem_ct, salt, kdf, nonce, ct) = format::read_kyber_payload_v6(&mut reader)?;
            let ss = if version >= format::VERSION_PQ_HYBRID {
                let seed: [u8; hybrid_kem::SECRET_LEN] = sk_bytes[..]
                    .try_into()
                    .map_err(|_| Error::Crypto("Decryption failed".into()))?;
                let seed = Zeroizing::new(seed);
                hybrid_kem::decapsulate(&seed, &kem_ct)?.to_vec()
            } else {
                nist_kyber::decapsulate(&kem_ct, &sk_bytes)?
            };
            let ss = Zeroizing::new(ss);
            if ss.len() < 32 {
                return Err(Error::Crypto("Decryption failed".into()));
            }
            let mut pw_key = crypto::derive_key(password, &salt, kdf)?;
            aes_key = kyber_hybrid_key(&ss, &pw_key, &salt, &kem_ct)?;
            crypto::secure_zero(&mut pw_key);
            let header = format::header_bytes(version, format_byte);
            let aad = [
                &header[..],
                &(kem_ct.len() as u32).to_le_bytes(),
                &kem_ct,
                &salt[..],
                &[kdf],
                &nonce[..],
            ]
            .concat();
            (nonce, ct, Some(aad))
        } else {
            let (kem_ct, nonce, ct) = format::read_kyber_payload(&mut reader)?;
            let ss = Zeroizing::new(nist_kyber::decapsulate(&kem_ct, &sk_bytes)?);
            if ss.len() < 32 {
                return Err(Error::Crypto("Decryption failed".into()));
            }
            aes_key = ss[..32]
                .try_into()
                .map_err(|_| Error::Crypto("Decryption failed".into()))?;
            (nonce, ct, None)
        };
        let dec = match &aad {
            Some(a) => crypto::aes_gcm_decrypt_aad(&aes_key, &nonce, &ciphertext_with_tag, a),
            None => crypto::aes_gcm_decrypt(&aes_key, &nonce, &ciphertext_with_tag),
        };
        crypto::secure_zero(&mut aes_key);
        let mut plaintext = Zeroizing::new(dec?);
        writer.write_all(&plaintext)?;
        crypto::secure_zero(plaintext.as_mut_slice());
        Ok(())
    })();
    result
}

/// Alıcı anahtar çifti üretir. Açık anahtar paylaşılır; gizli anahtar parola (Argon2id) ile şifrelenir.
pub fn generate_recipient_keys(
    password: &str,
    public_out: &mut dyn Write,
    secret_out: &mut dyn Write,
) -> Result<()> {
    validate_password(password)?;
    let (seed, pk) = hybrid_kem::generate_keypair()?;
    public_out.write_all(format::PUBKEY_MAGIC)?;
    public_out.write_all(&pk)?;
    let salt = crypto::gen_salt()?;
    let nonce = crypto::gen_nonce()?;
    let kdf = crypto::KDF_DEFAULT;
    let mut key = crypto::derive_key(password, &salt, kdf)?;
    let enc = crypto::aes_gcm_encrypt_aad(&key, &nonce, &seed[..], format::PUBKEY_MAGIC);
    crypto::secure_zero(&mut key);
    format::write_encrypted_secret_key(secret_out, 3, &salt, kdf, &nonce, &enc?)
}

fn read_public_key(r: &mut dyn Read) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.take((format::PUBKEY_MAGIC.len() + hybrid_kem::PUBLIC_LEN + 1) as u64)
        .read_to_end(&mut buf)?;
    if buf.len() != format::PUBKEY_MAGIC.len() + hybrid_kem::PUBLIC_LEN
        || !buf.starts_with(format::PUBKEY_MAGIC)
    {
        return Err(Error::Format("Invalid public key file".into()));
    }
    Ok(buf.split_off(format::PUBKEY_MAGIC.len()))
}

fn recipient_stream_key(ss: &[u8; 32], aad: &[u8]) -> Result<[u8; crypto::KEY_LEN]> {
    let okm = Zeroizing::new(crypto::hkdf_expand(
        ss,
        aad,
        crypto::KEY_LEN,
        Some(b"kaotik-v7-recipient"),
    )?);
    let mut k = [0u8; crypto::KEY_LEN];
    k.copy_from_slice(&okm);
    Ok(k)
}

/// Alıcı modu: alıcının açık anahtarına (ML-KEM-768 + X25519) şifreler; gönderici parola bilmez.
/// Düzen: başlık | KEM şifreli metni | nonce öneki(7) | STREAM blokları.
pub fn encrypt_to_recipient<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    public_key: &mut dyn Read,
) -> Result<()> {
    let pk = read_public_key(public_key)?;
    let (kem_ct, ss) = hybrid_kem::encapsulate(&pk)?;
    let mut prefix = [0u8; 7];
    crypto::random_bytes(&mut prefix)?;
    let header = format::header_bytes(format::VERSION_PQ_HYBRID, format::FORMAT_RECIPIENT);
    let aad = [&header[..], &kem_ct, &prefix[..]].concat();
    let mut key = recipient_stream_key(&ss, &aad)?;
    writer.write_all(&aad)?;
    let r = stream_encrypt(&mut reader, &mut writer, &key, &prefix, &aad);
    crypto::secure_zero(&mut key);
    r
}

/// Alıcı modu dosyasını gizli anahtar dosyası + parola ile çözer.
pub fn decrypt_from_recipient<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
    secret_key: &mut dyn Read,
) -> Result<()> {
    validate_password(password)?;
    let (_, salt, kdf, nonce, enc) = format::read_encrypted_secret_key(secret_key)?;
    let mut key = crypto::derive_key(password, &salt, kdf)?;
    let seed = crypto::aes_gcm_decrypt_aad(&key, &nonce, &enc, format::PUBKEY_MAGIC);
    crypto::secure_zero(&mut key);
    let seed = Zeroizing::new(seed?);
    let seed: Zeroizing<[u8; hybrid_kem::SECRET_LEN]> = Zeroizing::new(
        seed[..]
            .try_into()
            .map_err(|_| Error::Crypto("Decryption failed".into()))?,
    );
    let (version, format_byte) = format::read_header(&mut reader)?;
    if format_byte != format::FORMAT_RECIPIENT {
        return Err(Error::Format("Not a recipient format file".into()));
    }
    let mut kem_ct = vec![0u8; hybrid_kem::CIPHERTEXT_LEN];
    reader.read_exact(&mut kem_ct)?;
    let mut prefix = [0u8; 7];
    reader.read_exact(&mut prefix)?;
    let ss = hybrid_kem::decapsulate(&seed, &kem_ct)?;
    let aad = [
        &format::header_bytes(version, format_byte)[..],
        &kem_ct,
        &prefix[..],
    ]
    .concat();
    let mut stream_key = recipient_stream_key(&ss, &aad)?;
    let r = stream_decrypt(&mut reader, &mut writer, &stream_key, &prefix, &aad);
    crypto::secure_zero(&mut stream_key);
    r
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
            if version >= format::VERSION_AEAD_BOUND {
                let _ = format::read_aes_stream_start(&mut reader)?;
                loop {
                    let mut frame = [0u8; 5];
                    reader.read_exact(&mut frame)?;
                    if frame[0] > 1 {
                        return Err(Error::Format("Invalid stream frame".into()));
                    }
                    let len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
                    if len > AES_CHUNK_SIZE + crypto::TAG_LEN {
                        return Err(Error::Format("Chunk size exceeds limit".into()));
                    }
                    std::io::copy(&mut (&mut reader).take(len as u64), &mut std::io::sink())?;
                    if frame[0] == 1 {
                        break;
                    }
                }
            } else if version >= format::VERSION_AES_CHUNKED {
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
            if version >= format::VERSION_AEAD_BOUND {
                let _ = format::read_kyber_payload_v6(&mut reader)?;
            } else {
                let (_, _, _) = format::read_kyber_payload(&mut reader)?;
            }
        }
        format::FORMAT_RECIPIENT => {
            let mut skip = vec![0u8; hybrid_kem::CIPHERTEXT_LEN + 7];
            reader.read_exact(&mut skip)?;
        }
        _ => return Err(Error::Format("Unknown format byte".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaotic;
    use crate::crypto::SALT_LEN;
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
        let (s, kdf, n, c) =
            read_kaotik_payload(&mut std::io::Cursor::new(&v2_payload), 2).unwrap();
        assert_eq!(
            kdf, 0,
            "v2 format has no KDF byte, should default to PBKDF2"
        );
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
        let err =
            decrypt_kaotik(Cursor::new(&cipher), &mut dec, "WrongPassword123!@#").unwrap_err();
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
    fn test_kaotik_layers_deterministic_with_fixed_salt() {
        let salt = [7u8; SALT_LEN];
        let plain = b"Deterministic chaos layer check";
        let mut first = plain.to_vec();
        let mut second = plain.to_vec();

        chaotic::apply_chaotic_xor_layers(&mut first, TEST_PASSWORD, &salt).unwrap();
        chaotic::apply_chaotic_xor_layers(&mut second, TEST_PASSWORD, &salt).unwrap();
        assert_eq!(first, second);

        chaotic::reverse_chaotic_xor_layers(&mut first, TEST_PASSWORD, &salt).unwrap();
        assert_eq!(first, plain);
    }

    #[test]
    fn test_corrupted_file_fails() {
        let mut dec = Vec::new();
        let bad: &[u8] = b"NOT_KAOS\x00\x00\x00";
        assert!(decrypt_kaotik(Cursor::new(bad), &mut dec, TEST_PASSWORD).is_err());
    }

    #[test]
    fn test_kaotik_tampered_ciphertext_fails_auth() {
        let plain = b"tamper me";
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();

        // Header(7) + salt(32) + kdf(1) + nonce(12) = ciphertext start.
        let ct_offset = 7 + 32 + 1 + 12;
        cipher[ct_offset] ^= 0x01;

        let mut dec = Vec::new();
        let err = decrypt_kaotik(Cursor::new(&cipher), &mut dec, TEST_PASSWORD).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn test_kaotik_encrypt_uses_fresh_salt_and_nonce() {
        let plain = b"same input, fresh metadata";
        let mut first = Vec::new();
        let mut second = Vec::new();

        encrypt_kaotik(Cursor::new(&plain[..]), &mut first, TEST_PASSWORD).unwrap();
        encrypt_kaotik(Cursor::new(&plain[..]), &mut second, TEST_PASSWORD).unwrap();

        // Header(7) sonrası metadata: salt(32) + kdf(1) + nonce(12).
        let meta_start = 7;
        let meta_end = meta_start + 32 + 1 + 12;
        assert_ne!(&first[meta_start..meta_end], &second[meta_start..meta_end]);
    }

    #[test]
    fn test_kaotik_header_uses_padded_version() {
        let plain = b"header version check";
        let mut cipher = Vec::new();
        encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
        let mut cur = Cursor::new(&cipher);
        let (version, fmt) = read_header(&mut cur).unwrap();
        assert_eq!(fmt, FORMAT_KAOTIK);
        assert_eq!(version, format::VERSION_AEAD_BOUND);
    }

    #[test]
    fn test_kaotik_random_padding_obfuscates_length() {
        let plain = vec![0x42_u8; 1024];
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let mut cipher = Vec::new();
            encrypt_kaotik(Cursor::new(&plain[..]), &mut cipher, TEST_PASSWORD).unwrap();
            lengths.insert(cipher.len());
        }
        assert!(
            lengths.len() > 1,
            "random padding should produce varying ciphertext lengths"
        );
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

    fn aes_cipher(plain: &[u8]) -> Vec<u8> {
        let mut c = Vec::new();
        encrypt_aes(Cursor::new(plain), &mut c, TEST_PASSWORD).unwrap();
        c
    }

    #[test]
    fn test_v6_aes_stream_roundtrip_multi_chunk_and_exact_boundary() {
        for len in [
            0usize,
            1,
            AES_CHUNK_SIZE,
            AES_CHUNK_SIZE + 1,
            3 * AES_CHUNK_SIZE,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let c = aes_cipher(&plain);
            assert_eq!(&c[4..6], &format::VERSION_AEAD_BOUND.to_le_bytes());
            let mut d = Vec::new();
            decrypt_aes(Cursor::new(&c), &mut d, TEST_PASSWORD).unwrap();
            assert_eq!(d, plain, "len {}", len);
        }
    }

    #[test]
    fn test_v6_aes_stream_detects_truncation_and_trailing_data() {
        let plain = vec![7u8; 2 * AES_CHUNK_SIZE + 10];
        let c = aes_cipher(&plain);
        // İlk bloğun sonunda kes: son-blok bayrağı olmadığından reddedilmeli.
        let first_frame_end = 7 + 32 + 1 + 7 + 5 + AES_CHUNK_SIZE + 16;
        let mut d = Vec::new();
        assert!(decrypt_aes(Cursor::new(&c[..first_frame_end]), &mut d, TEST_PASSWORD).is_err());
        // Bayrağı 1 yaparak erken bitirme denemesi: nonce değiştiğinden doğrulama başarısız.
        let mut forged = c[..first_frame_end].to_vec();
        forged[7 + 32 + 1 + 7] = 1;
        assert!(decrypt_aes(Cursor::new(&forged), &mut Vec::new(), TEST_PASSWORD).is_err());
        let mut extra = c.clone();
        extra.push(0);
        assert!(decrypt_aes(Cursor::new(&extra), &mut Vec::new(), TEST_PASSWORD).is_err());
    }

    #[test]
    fn test_v6_header_and_kdf_tamper_rejected() {
        let mut c = Vec::new();
        encrypt_kaotik(Cursor::new(b"header binding"), &mut c, TEST_PASSWORD).unwrap();
        let mut bad = c.clone();
        bad[7 + 32] = crypto::KDF_ARGON2; // KDF düşürme denemesi
        assert!(decrypt_kaotik(Cursor::new(&bad), &mut Vec::new(), TEST_PASSWORD).is_err());
        let mut bad = c.clone();
        bad[7 + 32] = 9;
        assert!(decrypt_kaotik(Cursor::new(&bad), &mut Vec::new(), TEST_PASSWORD).is_err());
        let mut bad = c.clone();
        bad[4] = 5; // sürüm düşürme
        assert!(decrypt_kaotik(Cursor::new(&bad), &mut Vec::new(), TEST_PASSWORD).is_err());
    }

    #[test]
    fn test_v6_kyber_hybrid_roundtrip_and_wrong_password() {
        let plain = b"post-quantum hybrid";
        let mut c = Vec::new();
        let mut key = Vec::new();
        encrypt_kyber(Cursor::new(plain), &mut c, TEST_PASSWORD, &mut key).unwrap();
        let mut d = Vec::new();
        decrypt_kyber(
            Cursor::new(&c),
            &mut d,
            TEST_PASSWORD,
            &mut Cursor::new(&key),
        )
        .unwrap();
        assert_eq!(d, plain);
        assert!(verify_file(Cursor::new(&c)).is_ok());
        let mut bad = c.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(decrypt_kyber(
            Cursor::new(&bad),
            &mut Vec::new(),
            TEST_PASSWORD,
            &mut Cursor::new(&key)
        )
        .is_err());
        assert!(decrypt_kyber(
            Cursor::new(&c),
            &mut Vec::new(),
            "OtherPassword456!@#",
            &mut Cursor::new(&key)
        )
        .is_err());
    }

    #[test]
    fn test_unknown_kdf_rejected() {
        assert!(crypto::derive_key("x", &[0u8; 32], 77).is_err());
    }

    #[test]
    fn test_kaotik_roundtrip_larger_than_hkdf_limit() {
        let plain: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
        let mut c = Vec::new();
        encrypt_kaotik(Cursor::new(&plain), &mut c, TEST_PASSWORD).unwrap();
        let mut d = Vec::new();
        decrypt_kaotik(Cursor::new(&c), &mut d, TEST_PASSWORD).unwrap();
        assert_eq!(d, plain);
    }

    #[test]
    fn test_legacy_fixtures_still_decrypt() {
        use sha2::{Digest, Sha256};
        // Fixture'lar eski CLI ile üretildi: CLI parolayı bağlam parolasına çevirir (cli_ext::derive_context_password).
        let hex: String = Sha256::digest(TEST_PASSWORD.as_bytes())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let ctx = format!("{}|CTX:{}A1!", TEST_PASSWORD, &hex[..16]);
        let plain: &[u8] = include_bytes!("../tests/fixtures/plain.txt");
        let mut out = Vec::new();
        decrypt_kaotik(
            Cursor::new(&include_bytes!("../tests/fixtures/v5_kaotik.kaos")[..]),
            &mut out,
            &ctx,
        )
        .unwrap();
        assert_eq!(out, plain);
        let mut out = Vec::new();
        decrypt_aes(
            Cursor::new(&include_bytes!("../tests/fixtures/v4_aes.kaos")[..]),
            &mut out,
            &ctx,
        )
        .unwrap();
        assert_eq!(out, plain);
        let mut out = Vec::new();
        let mut key = Cursor::new(&include_bytes!("../tests/fixtures/v2_kyber.key")[..]);
        decrypt_kyber(
            Cursor::new(&include_bytes!("../tests/fixtures/v2_kyber.kaos")[..]),
            &mut out,
            &ctx,
            &mut key,
        )
        .unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn test_kyber_v7_uses_hybrid_pq_kem() {
        let mut c = Vec::new();
        let mut key = Vec::new();
        encrypt_kyber(Cursor::new(b"v7"), &mut c, TEST_PASSWORD, &mut key).unwrap();
        assert_eq!(&c[4..6], &format::VERSION_PQ_HYBRID.to_le_bytes());
        let ct_len = u32::from_le_bytes(c[7..11].try_into().unwrap()) as usize;
        assert_eq!(ct_len, hybrid_kem::CIPHERTEXT_LEN);
        let mut d = Vec::new();
        decrypt_kyber(
            Cursor::new(&c),
            &mut d,
            TEST_PASSWORD,
            &mut Cursor::new(&key),
        )
        .unwrap();
        assert_eq!(d, b"v7");
    }

    #[test]
    fn test_recipient_mode_roundtrip_and_rejections() {
        let (mut pubk, mut sec) = (Vec::new(), Vec::new());
        generate_recipient_keys(TEST_PASSWORD, &mut pubk, &mut sec).unwrap();
        let plain: Vec<u8> = (0..(AES_CHUNK_SIZE * 2 + 5)).map(|i| i as u8).collect();
        let mut c = Vec::new();
        encrypt_to_recipient(Cursor::new(&plain), &mut c, &mut Cursor::new(&pubk)).unwrap();
        assert!(verify_file(Cursor::new(&c)).is_ok());
        let mut d = Vec::new();
        decrypt_from_recipient(
            Cursor::new(&c),
            &mut d,
            TEST_PASSWORD,
            &mut Cursor::new(&sec),
        )
        .unwrap();
        assert_eq!(d, plain);
        assert!(decrypt_from_recipient(
            Cursor::new(&c),
            &mut Vec::new(),
            "OtherPassword456!@#",
            &mut Cursor::new(&sec)
        )
        .is_err());
        let (mut pub2, mut sec2) = (Vec::new(), Vec::new());
        generate_recipient_keys(TEST_PASSWORD, &mut pub2, &mut sec2).unwrap();
        assert!(decrypt_from_recipient(
            Cursor::new(&c),
            &mut Vec::new(),
            TEST_PASSWORD,
            &mut Cursor::new(&sec2)
        )
        .is_err());
        let mut bad = c.clone();
        bad[20] ^= 1; // KEM şifreli metni
        assert!(decrypt_from_recipient(
            Cursor::new(&bad),
            &mut Vec::new(),
            TEST_PASSWORD,
            &mut Cursor::new(&sec)
        )
        .is_err());
        assert!(encrypt_to_recipient(
            Cursor::new(b"x"),
            &mut Vec::new(),
            &mut Cursor::new(&pubk[..100])
        )
        .is_err());
    }
}
