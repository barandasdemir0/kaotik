//! Yalnızca hash fonksiyonlarına dayanan imza: **SLH-DSA-SHAKE-256s** (NIST FIPS 205, kategori 5).
//!
//! Güvenliği sadece SHAKE256'nın tek yönlülüğüne dayanır; kafes veya eliptik eğri varsayımı yoktur.
//! Bu yüzden on yıllar ölçeğinde en muhafazakâr seçenektir. Bedeli: imza ~29 KiB ve imzalama yavaştır.
//! Önerilen kullanım: uzun ömürlü **kök kimlik** anahtarı (cihaz/kimlik anahtarlarını imzalamak,
//! yazılım sürümleri, arşiv belgeleri) — her sohbet mesajı için değil.
use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use slh_dsa::Shake256s;
use zeroize::Zeroizing;

pub const SECRET_LEN: usize = 128;
pub const PUBLIC_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 29792;

pub struct SlhSigningKey(slh_dsa::SigningKey<Shake256s>);

#[derive(Clone, PartialEq, Eq)]
pub struct SlhVerifyingKey(Vec<u8>);

impl SlhSigningKey {
    pub fn generate() -> Result<Self> {
        let mut seeds = Zeroizing::new([0u8; 96]);
        random_bytes(&mut seeds[..])?;
        Ok(Self(slh_dsa::SigningKey::<Shake256s>::slh_keygen_internal(
            &seeds[..32],
            &seeds[32..64],
            &seeds[64..],
        )))
    }

    pub fn verifying_key(&self) -> SlhVerifyingKey {
        let vk: &slh_dsa::VerifyingKey<Shake256s> = self.0.as_ref();
        SlhVerifyingKey(vk.to_vec())
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        slh_dsa::SigningKey::<Shake256s>::try_from(b)
            .map(Self)
            .map_err(|_| Error::Format("Invalid SLH-DSA secret key".into()))
    }

    /// Hedged (rastgeleleştirilmiş) imza; `ctx` ≤ 255 bayt.
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        let mut rnd = [0u8; 32];
        random_bytes(&mut rnd)?;
        self.0
            .try_sign_with_context(msg, ctx, Some(&rnd))
            .map(|s| s.to_vec())
            .map_err(|_| Error::Format("Context too long".into()))
    }
}

impl SlhVerifyingKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        slh_dsa::VerifyingKey::<Shake256s>::try_from(b)
            .map_err(|_| Error::Format("Invalid SLH-DSA public key".into()))?;
        Ok(Self(b.to_vec()))
    }

    pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let (Ok(vk), Ok(s)) = (
            slh_dsa::VerifyingKey::<Shake256s>::try_from(&self.0[..]),
            slh_dsa::Signature::<Shake256s>::try_from(sig),
        ) else {
            return false;
        };
        vk.try_verify_with_context(msg, ctx, &s).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow without optimizations; run with --release")]
    fn slh_sign_verify() {
        let sk = SlhSigningKey::generate().unwrap();
        let sk = SlhSigningKey::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk.to_bytes().len(), SECRET_LEN);
        let vk = SlhVerifyingKey::from_bytes(&sk.verifying_key().to_bytes()).unwrap();
        assert_eq!(vk.to_bytes().len(), PUBLIC_LEN);
        let sig = sk.sign(b"kok kimlik", b"root").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(vk.verify(b"kok kimlik", b"root", &sig));
        assert!(!vk.verify(b"kok kimlik!", b"root", &sig));
        assert!(!vk.verify(b"kok kimlik", b"other", &sig));
    }
}
