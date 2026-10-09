//! Uygulama giriş parolaları için **hash** (şifreleme değil). Veritabanında yalnızca
//! PHC dizesi (`$argon2id$v=19$m=...`) saklanır; parola geri elde edilemez.
use crate::error::{Error, Result};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id: 64 MiB bellek, 3 iterasyon, 1 paralellik (OWASP/RFC 9106 ile uyumlu).
fn hasher() -> Result<Argon2<'static>> {
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Parolayı hash'ler; dönen PHC dizesi tuz ve parametreleri içerir.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Sabit zamanlı doğrulama. Bozuk/yabancı hash → `false`.
pub fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else { return false };
    if parsed.algorithm.as_str() != "argon2id" {
        return false;
    }
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Kayıtlı hash eski/zayıf parametrelerle mi üretilmiş? (girişte yeniden hash'lemek için)
pub fn needs_rehash(phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else { return true };
    let Ok(p) = Params::try_from(&parsed) else { return true };
    parsed.algorithm.as_str() != "argon2id" || p.m_cost() < 65536 || p.t_cost() < 3
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_and_verify() {
        let h = hash_password("dogru parola").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("dogru parola", &h));
        assert!(!verify_password("yanlis", &h));
        assert!(!verify_password("x", "garbage"));
        assert!(!needs_rehash(&h));
    }
}
