//! Gizli anahtarların güvenli saklanması.
//!
//! 1. **Parolalı anahtar kutusu** (`lock` / `unlock`): Argon2id (parametreler dosyada saklı,
//!    ileride artırılabilir) + XChaCha20-Poly1305. Her platformda çalışır.
//! 2. **İşletim sistemi anahtar zinciri** (`--features keyring`): macOS/iOS Keychain,
//!    Windows Credential Manager, Linux kernel keyutils. Anahtar diskte düz durmaz;
//!    donanım destekli depolama (Secure Enclave / TPM) işletim sistemi tarafından kullanılır.
//!
//! Öneri: rastgele bir "cihaz anahtarı" üret (`hybrid::generate_key`), onu işletim sistemi
//! anahtar zincirine koy; uygulama verilerini (ratchet oturumları, kimlik anahtarları) bu
//! anahtarla `seal` et. Yedek/taşıma için `lock` ile parolalı kopya çıkar.
use crate::error::{Error, Result};
use crate::hybrid;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"KKEY";
const VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + 12;

/// Argon2id maliyet parametreleri.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 256 MiB, 4 geçiş: uzun ömürlü anahtarlar için etkileşimli girişten daha ağır.
    fn default() -> Self {
        Self { m_cost_kib: 256 * 1024, t_cost: 4, p_cost: 1 }
    }
}

impl KdfParams {
    /// Mobil/düşük bellekli cihazlar için (64 MiB, 3 geçiş — OWASP alt sınırı).
    pub fn moderate() -> Self {
        Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 1 }
    }
}

fn derive(password: &[u8], salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // Zararlı dosyanın aşırı bellek istemesini engelle (en fazla 4 GiB, 64 geçiş).
    if p.m_cost_kib > 4 * 1024 * 1024 || p.t_cost > 64 || p.p_cost == 0 || p.p_cost > 16 {
        return Err(Error::Format("Unsupported KDF parameters".into()));
    }
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32)).map_err(|e| Error::Crypto(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(key)
}

/// Gizli veriyi parolayla kilitler.
pub fn lock(password: &str, secret: &[u8], params: KdfParams) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(Error::Password("Empty password".into()));
    }
    let mut salt = [0u8; SALT_LEN];
    crate::crypto::random_bytes(&mut salt)?;
    let mut hdr = Vec::with_capacity(HEADER_LEN);
    hdr.extend_from_slice(MAGIC);
    hdr.push(VERSION);
    hdr.extend_from_slice(&salt);
    for v in [params.m_cost_kib, params.t_cost, params.p_cost] {
        hdr.extend_from_slice(&v.to_be_bytes());
    }
    let key = derive(password.as_bytes(), &salt, params)?;
    let body = hybrid::seal(&key, secret, &hdr)?;
    hdr.extend_from_slice(&body);
    Ok(hdr)
}

/// `lock` çıktısını açar. Yanlış parola veya değiştirilmiş dosya → hata.
pub fn unlock(password: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let bad = || Error::Crypto("Decryption failed".into());
    if blob.len() < HEADER_LEN + hybrid::SEAL_OVERHEAD || &blob[..4] != MAGIC || blob[4] != VERSION {
        return Err(bad());
    }
    let (hdr, body) = blob.split_at(HEADER_LEN);
    let salt = &hdr[5..5 + SALT_LEN];
    let num = |i: usize| u32::from_be_bytes(hdr[5 + SALT_LEN + i * 4..5 + SALT_LEN + i * 4 + 4].try_into().expect("4"));
    let params = KdfParams { m_cost_kib: num(0), t_cost: num(1), p_cost: num(2) };
    let key = derive(password.as_bytes(), salt, params)?;
    hybrid::open(&key, body, hdr).map_err(|_| bad())
}

/// Parolayla akış şifreleme (sınırsız boyut): `KKEY başlığı (gövdesiz) || seal_stream`.
pub fn lock_stream<R: std::io::Read, W: std::io::Write>(password: &str, params: KdfParams, r: R, mut w: W) -> Result<()> {
    if password.is_empty() {
        return Err(Error::Password("Empty password".into()));
    }
    let mut salt = [0u8; SALT_LEN];
    crate::crypto::random_bytes(&mut salt)?;
    let mut hdr = Vec::with_capacity(HEADER_LEN);
    hdr.extend_from_slice(b"KSPW");
    hdr.push(VERSION);
    hdr.extend_from_slice(&salt);
    for v in [params.m_cost_kib, params.t_cost, params.p_cost] {
        hdr.extend_from_slice(&v.to_be_bytes());
    }
    let key = derive(password.as_bytes(), &salt, params)?;
    w.write_all(&hdr)?;
    crate::stream::seal_stream(&key, &hdr, r, w)
}

pub fn unlock_stream<R: std::io::Read, W: std::io::Write>(password: &str, mut r: R, w: W) -> Result<()> {
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr).map_err(|_| Error::Crypto("Decryption failed".into()))?;
    if &hdr[..4] != b"KSPW" || hdr[4] != VERSION {
        return Err(Error::Crypto("Decryption failed".into()));
    }
    let num = |i: usize| u32::from_be_bytes(hdr[5 + SALT_LEN + i * 4..5 + SALT_LEN + i * 4 + 4].try_into().expect("4"));
    let params = KdfParams { m_cost_kib: num(0), t_cost: num(1), p_cost: num(2) };
    let key = derive(password.as_bytes(), &hdr[5..5 + SALT_LEN], params)?;
    crate::stream::open_stream(&key, &hdr, r, w)
}

/// Kutunun hangi parametrelerle kilitlendiği (parola gerekmez) — yükseltme kararı için.
pub fn params_of(blob: &[u8]) -> Option<KdfParams> {
    if blob.len() < HEADER_LEN || &blob[..4] != MAGIC {
        return None;
    }
    let num = |i: usize| u32::from_be_bytes(blob[5 + SALT_LEN + i * 4..5 + SALT_LEN + i * 4 + 4].try_into().ok().unwrap_or_default());
    Some(KdfParams { m_cost_kib: num(0), t_cost: num(1), p_cost: num(2) })
}

/// İşletim sistemi anahtar zinciri.
#[cfg(feature = "keyring")]
pub mod os {
    use crate::error::{Error, Result};
    use zeroize::Zeroizing;

    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(service, account).map_err(|e| Error::Crypto(format!("keyring: {e}")))
    }

    pub fn store(service: &str, account: &str, secret: &[u8]) -> Result<()> {
        entry(service, account)?.set_secret(secret).map_err(|e| Error::Crypto(format!("keyring: {e}")))
    }

    pub fn load(service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        entry(service, account)?
            .get_secret()
            .map(Zeroizing::new)
            .map_err(|e| Error::Crypto(format!("keyring: {e}")))
    }

    pub fn delete(service: &str, account: &str) -> Result<()> {
        entry(service, account)?.delete_credential().map_err(|e| Error::Crypto(format!("keyring: {e}")))
    }

    /// Kayıtlı cihaz anahtarını döndürür; yoksa yenisini üretip saklar.
    pub fn device_key(service: &str, account: &str) -> Result<Zeroizing<[u8; 32]>> {
        if let Ok(k) = load(service, account) {
            if k.len() == 32 {
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(&k);
                return Ok(out);
            }
        }
        let k = crate::hybrid::generate_key()?;
        store(service, account, &k[..])?;
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_unlock() {
        let p = KdfParams { m_cost_kib: 8 * 1024, t_cost: 1, p_cost: 1 };
        let blob = lock("parola", b"gizli anahtar", p).unwrap();
        assert_eq!(params_of(&blob), Some(p));
        assert_eq!(&unlock("parola", &blob).unwrap()[..], b"gizli anahtar");
        assert!(unlock("yanlis", &blob).is_err());
        let mut t = blob.clone();
        t[40] ^= 1; // parametre/başlık değişikliği tespit edilir
        assert!(unlock("parola", &t).is_err());
        assert!(lock("", b"x", p).is_err());
        let mut ct = Vec::new();
        lock_stream("pw", p, &b"buyuk dosya"[..], &mut ct).unwrap();
        let mut pt = Vec::new();
        unlock_stream("pw", &ct[..], &mut pt).unwrap();
        assert_eq!(pt, b"buyuk dosya");
        assert!(unlock_stream("px", &ct[..], &mut Vec::new()).is_err());
    }
}
