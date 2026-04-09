//! NIST FIPS 203 ML-KEM (Kyber-768): keypair, encapsulate, decapsulate. Kuantum direnci.
use crate::crypto;
use crate::error::{Error, Result};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

/// NIST Kyber-768 anahtar çifti (public + secret byte olarak saklanabilir).
/// Drop'da secret_key bellekten sıfırlanır.
pub struct NistKyberKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Drop for NistKyberKeypair {
    fn drop(&mut self) {
        crypto::secure_zero(self.secret_key.as_mut_slice());
    }
}

/// Paylaşılan gizlilik (32 bayt)
pub fn shared_secret_len() -> usize {
    kyber768::shared_secret_bytes()
}

pub fn generate_keypair() -> Result<NistKyberKeypair> {
    let (pk, sk) = kyber768::keypair();
    Ok(NistKyberKeypair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

/// Encapsulate: (shared_secret, ciphertext). shared_secret AES anahtarı olarak kullanılır.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = kyber768::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::Crypto(format!("Kyber public key: {:?}", e)))?;
    let (ss, ct) = kyber768::encapsulate(&pk);
    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let ct = kyber768::Ciphertext::from_bytes(ciphertext)
        .map_err(|e| Error::Crypto(format!("Kyber ciphertext: {:?}", e)))?;
    let sk = kyber768::SecretKey::from_bytes(secret_key)
        .map_err(|e| Error::Crypto(format!("Kyber secret key: {:?}", e)))?;
    let ss = kyber768::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}
