//! Hibrit post-kuantum KEM: ML-KEM-768 (NIST FIPS 203) + X25519 (X-Wing tarzı birleştirme).
//! Paylaşılan sır ancak İKİ problem birden çözülürse elde edilir: kafes (lattice) problemi ve
//! eliptik eğri ayrık logaritması. Kuantum bilgisayar X25519'u kırsa ML-KEM, ML-KEM'de
//! beklenmedik bir zayıflık bulunsa X25519 korur.
use crate::crypto;
use crate::error::{Error, Result};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use zeroize::Zeroizing;

/// Gizli anahtar: 32 bayt rastgele tohum (ML-KEM ve X25519 anahtarları bundan türetilir).
pub const SECRET_LEN: usize = 32;
/// Açık anahtar: ML-KEM ek (1184) + X25519 (32).
pub const PUBLIC_LEN: usize = 1184 + 32;
/// KEM şifreli metni: ML-KEM ct (1088) + geçici X25519 açık anahtarı (32).
pub const CIPHERTEXT_LEN: usize = 1088 + 32;

const LABEL: &[u8] = b"kaotik-xwing-mlkem768-x25519-v1";

fn expand(
    seed: &[u8; SECRET_LEN],
) -> Result<(DecapsulationKey<MlKem768>, x25519_dalek::StaticSecret)> {
    let okm = Zeroizing::new(crypto::hkdf_expand(
        seed,
        b"kaotik-xwing-keygen",
        64 + 32,
        None,
    )?);
    let mut mlkem_seed = Zeroizing::new([0u8; 64]);
    mlkem_seed.copy_from_slice(&okm[..64]);
    let mut x = Zeroizing::new([0u8; 32]);
    x.copy_from_slice(&okm[64..]);
    let dk = DecapsulationKey::<MlKem768>::from_seed((*mlkem_seed).into());
    Ok((dk, x25519_dalek::StaticSecret::from(*x)))
}

fn combine(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8], pk_x: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let ikm = Zeroizing::new([ss_m, &ss_x[..]].concat());
    let info = [LABEL, ct_x, pk_x].concat();
    let okm = Zeroizing::new(crypto::hkdf_expand(&ikm, &info, 32, None)?);
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&okm);
    Ok(k)
}

/// Yeni anahtar çifti: (gizli tohum, açık anahtar).
pub fn generate_keypair() -> Result<(Zeroizing<[u8; SECRET_LEN]>, Vec<u8>)> {
    let mut seed = Zeroizing::new([0u8; SECRET_LEN]);
    crypto::random_bytes(&mut seed[..])?;
    let pk = public_key(&seed)?;
    Ok((seed, pk))
}

pub fn public_key(seed: &[u8; SECRET_LEN]) -> Result<Vec<u8>> {
    let (dk, x) = expand(seed)?;
    let ek = dk.encapsulation_key().to_bytes();
    Ok([&ek[..], x25519_dalek::PublicKey::from(&x).as_bytes()].concat())
}

/// Açık anahtara kapsülleme: (KEM şifreli metni, 32 baytlık paylaşılan sır).
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    if public_key.len() != PUBLIC_LEN {
        return Err(Error::Crypto("Invalid hybrid public key".into()));
    }
    let ek_bytes = public_key[..1184]
        .try_into()
        .map_err(|_| Error::Crypto("Invalid hybrid public key".into()))?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_bytes)
        .map_err(|_| Error::Crypto("Invalid ML-KEM key".into()))?;
    let pk_x: [u8; 32] = public_key[1184..].try_into().unwrap();
    let (ct_m, ss_m) = ek.encapsulate();

    let mut eph = Zeroizing::new([0u8; 32]);
    crypto::random_bytes(&mut eph[..])?;
    let eph = x25519_dalek::StaticSecret::from(*eph);
    let ct_x = x25519_dalek::PublicKey::from(&eph);
    let ss_x = Zeroizing::new(
        *eph.diffie_hellman(&x25519_dalek::PublicKey::from(pk_x))
            .as_bytes(),
    );
    let ct: Vec<u8> = [&ct_m[..], &ct_x.as_bytes()[..]].concat();
    let k = combine(&ss_m[..], &ss_x, ct_x.as_bytes(), &pk_x)?;
    Ok((ct, k))
}

pub fn decapsulate(seed: &[u8; SECRET_LEN], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if ct.len() != CIPHERTEXT_LEN {
        return Err(Error::Crypto("Decryption failed".into()));
    }
    let (dk, x) = expand(seed)?;
    let ct_m = ct[..1088]
        .try_into()
        .map_err(|_| Error::Crypto("Decryption failed".into()))?;
    let ss_m = dk.decapsulate(&ct_m);
    let ct_x: [u8; 32] = ct[1088..].try_into().unwrap();
    let ss_x = Zeroizing::new(
        *x.diffie_hellman(&x25519_dalek::PublicKey::from(ct_x))
            .as_bytes(),
    );
    let pk_x = x25519_dalek::PublicKey::from(&x);
    combine(&ss_m[..], &ss_x, &ct_x, pk_x.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_key() {
        let (sk, pk) = generate_keypair().unwrap();
        assert_eq!(pk.len(), PUBLIC_LEN);
        let (ct, k1) = encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        assert_eq!(*decapsulate(&sk, &ct).unwrap(), *k1);
        let (other, _) = generate_keypair().unwrap();
        assert_ne!(*decapsulate(&other, &ct).unwrap(), *k1);
        // Klasik yarının değiştirilmesi de sırrı değiştirir (iki yarı birlikte bağlı).
        let mut bad = ct.clone();
        bad[CIPHERTEXT_LEN - 1] ^= 1;
        assert_ne!(*decapsulate(&sk, &bad).unwrap(), *k1);
        assert!(encapsulate(&pk[..10]).is_err());
    }
}
