//! Büyük dosyalar / akışlar için parçalı kimlik doğrulamalı şifreleme (STREAM yapısı,
//! Hoang–Reyhanitabar–Rogaway–Vizár). Bellek kullanımı sabittir (~64 KiB).
//!
//! Biçim: `"KSTR" || ver(1) || nonce_prefix(19) || { u32 len || chunk_ct }*`
//! Her parça nonce'u = prefix(19) || sayaç(4, BE) || son_bayrağı(1). Son parça bayrağı sayesinde
//! **kesme (truncation)**, parça **sırasını değiştirme** ve **ekleme** saldırıları tespit edilir.
//! Çözme sırasında doğrulanmamış veri yazılmaz; ancak son parça doğrulanmadan önceki parçalar
//! yazılmış olabilir → çağıran, `Ok` dönmeden çıktıyı kesin kabul etmemelidir.
use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use crate::hybrid::{self, HybridKemPublicKey, HybridKemSecretKey, KEM_CIPHERTEXT_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::io::{Read, Write};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"KSTR";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 19;
pub const CHUNK_SIZE: usize = 64 * 1024;
const TAG_LEN: usize = 16;

fn nonce(prefix: &[u8; PREFIX_LEN], counter: u32, last: bool) -> XNonce {
    let mut n = [0u8; 24];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..23].copy_from_slice(&counter.to_be_bytes());
    n[23] = last as u8;
    XNonce::from(n)
}

fn header_aad(prefix: &[u8; PREFIX_LEN], aad: &[u8]) -> Vec<u8> {
    [&MAGIC[..], &[VERSION], prefix, aad].concat()
}

/// Okuyucunun tamamını tampon dolana kadar okur (kısa okuma toleranslı).
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// 32 baytlık anahtarla akışı şifreler.
pub fn seal_stream<R: Read, W: Write>(key: &[u8; 32], aad: &[u8], mut r: R, mut w: W) -> Result<()> {
    let mut prefix = [0u8; PREFIX_LEN];
    random_bytes(&mut prefix)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let base_aad = header_aad(&prefix, aad);
    w.write_all(MAGIC)?;
    w.write_all(&[VERSION])?;
    w.write_all(&prefix)?;
    let mut cur = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut next = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut cur_len = fill(&mut r, &mut cur)?;
    let mut counter: u32 = 0;
    loop {
        // Sonraki parçayı önceden okuyarak bunun son parça olup olmadığını belirle.
        let next_len = if cur_len == CHUNK_SIZE { fill(&mut r, &mut next)? } else { 0 };
        let last = next_len == 0;
        let ct = cipher
            .encrypt(&nonce(&prefix, counter, last), Payload { msg: &cur[..cur_len], aad: &base_aad })
            .map_err(|_| Error::Crypto("Encryption failed".into()))?;
        w.write_all(&(ct.len() as u32).to_be_bytes())?;
        w.write_all(&ct)?;
        if last {
            break;
        }
        counter = counter.checked_add(1).ok_or_else(|| Error::Crypto("Stream too long".into()))?;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
    w.flush()?;
    Ok(())
}

/// `seal_stream` çıktısını çözer.
pub fn open_stream<R: Read, W: Write>(key: &[u8; 32], aad: &[u8], mut r: R, mut w: W) -> Result<()> {
    let bad = || Error::Crypto("Decryption failed".into());
    let mut hdr = [0u8; 4 + 1 + PREFIX_LEN];
    if fill(&mut r, &mut hdr)? != hdr.len() || &hdr[..4] != MAGIC || hdr[4] != VERSION {
        return Err(bad());
    }
    let prefix: [u8; PREFIX_LEN] = hdr[5..].try_into().expect("19");
    let cipher = XChaCha20Poly1305::new(key.into());
    let base_aad = header_aad(&prefix, aad);
    let mut counter: u32 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE + TAG_LEN];
    loop {
        let mut len_b = [0u8; 4];
        if fill(&mut r, &mut len_b)? != 4 {
            return Err(bad()); // son parça bayrağı görülmeden akış bitti → kesilmiş
        }
        let len = u32::from_be_bytes(len_b) as usize;
        if !(TAG_LEN..=CHUNK_SIZE + TAG_LEN).contains(&len) || fill(&mut r, &mut buf[..len])? != len {
            return Err(bad());
        }
        let payload = |msg| Payload { msg, aad: &base_aad[..] };
        if let Ok(pt) = cipher.decrypt(&nonce(&prefix, counter, false), payload(&buf[..len])) {
            let pt = Zeroizing::new(pt);
            if pt.len() != CHUNK_SIZE {
                return Err(bad());
            }
            w.write_all(&pt)?;
        } else {
            let pt = Zeroizing::new(cipher.decrypt(&nonce(&prefix, counter, true), payload(&buf[..len])).map_err(|_| bad())?);
            // Son parçadan sonra veri olmamalı (ekleme saldırısı).
            let mut extra = [0u8; 1];
            if fill(&mut r, &mut extra)? != 0 {
                return Err(bad());
            }
            w.write_all(&pt)?;
            w.flush()?;
            return Ok(());
        }
        counter = counter.checked_add(1).ok_or_else(bad)?;
    }
}

/// Alıcının hibrit açık anahtarına akış şifreleme: `kem_ct || seal_stream(...)`.
pub fn seal_stream_to<R: Read, W: Write>(recipient: &HybridKemPublicKey, aad: &[u8], r: R, mut w: W) -> Result<()> {
    let (ct, ss) = recipient.encapsulate()?;
    let key = hybrid::derive_subkey(&ss[..], b"stream_to", &ct);
    w.write_all(&ct)?;
    seal_stream(&key, &[&ct[..], aad].concat(), r, w)
}

pub fn open_stream_from<R: Read, W: Write>(sk: &HybridKemSecretKey, aad: &[u8], mut r: R, w: W) -> Result<()> {
    let mut ct = vec![0u8; KEM_CIPHERTEXT_LEN];
    if fill(&mut r, &mut ct)? != ct.len() {
        return Err(Error::Crypto("Decryption failed".into()));
    }
    let ss = sk.decapsulate(&ct)?;
    let key = hybrid::derive_subkey(&ss[..], b"stream_to", &ct);
    open_stream(&key, &[&ct[..], aad].concat(), r, w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let key = hybrid::generate_key().unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let mut ct = Vec::new();
        seal_stream(&key, b"f", &data[..], &mut ct).unwrap();
        let mut pt = Vec::new();
        open_stream(&key, b"f", &ct[..], &mut pt).unwrap();
        assert_eq!(pt, data, "len {len}");
        // Kesme: son parçayı at
        if len > CHUNK_SIZE {
            let cut = 4 + 1 + PREFIX_LEN + 4 + CHUNK_SIZE + TAG_LEN;
            assert!(open_stream(&key, b"f", &ct[..cut], &mut Vec::new()).is_err());
        }
        // Ekleme
        let mut ext = ct.clone();
        ext.push(0);
        assert!(open_stream(&key, b"f", &ext[..], &mut Vec::new()).is_err());
        assert!(open_stream(&key, b"g", &ct[..], &mut Vec::new()).is_err());
    }

    #[test]
    fn stream_sizes() {
        for len in [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 5] {
            roundtrip(len);
        }
    }

    #[test]
    fn stream_to_recipient() {
        let sk = HybridKemSecretKey::generate().unwrap();
        let data = vec![9u8; 200_000];
        let mut ct = Vec::new();
        seal_stream_to(&sk.public_key(), b"", &data[..], &mut ct).unwrap();
        let mut pt = Vec::new();
        open_stream_from(&sk, b"", &ct[..], &mut pt).unwrap();
        assert_eq!(pt, data);
    }
}
