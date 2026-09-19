//! NIST FIPS 203 ML-KEM (Kyber-1024, en yüksek NIST güvenlik seviyesi): keypair, encapsulate,
//! decapsulate. Ayrıca X25519 ile birleştirilmiş **hibrit** KEM: nihai anahtar hem kafes
//! (lattice) hem eliptik eğri (ECDH) zorluk varsayımına dayanır — biri ileride kırılsa bile
//! diğeri anahtarı korur (TLS 1.3 hibrit modlarındaki standart yaklaşımla aynı ilke).
use crate::crypto;
use crate::error::{Error, Result};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};

/// NIST Kyber-1024 anahtar çifti (public + secret byte olarak saklanabilir).
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
    kyber1024::shared_secret_bytes()
}

pub fn generate_keypair() -> Result<NistKyberKeypair> {
    let (pk, sk) = kyber1024::keypair();
    Ok(NistKyberKeypair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

/// Encapsulate: (shared_secret, ciphertext). shared_secret AES anahtarı olarak kullanılır.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = kyber1024::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::Crypto(format!("Kyber public key: {:?}", e)))?;
    let (ss, ct) = kyber1024::encapsulate(&pk);
    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|e| Error::Crypto(format!("Kyber ciphertext: {:?}", e)))?;
    let sk = kyber1024::SecretKey::from_bytes(secret_key)
        .map_err(|e| Error::Crypto(format!("Kyber secret key: {:?}", e)))?;
    let ss = kyber1024::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

/// Hibrit anahtar çifti: Kyber-1024 (post-kuantum) + X25519 statik anahtar (klasik ECDH).
/// Her iki gizli anahtar da parola ile şifrelenmiş tek dosyada saklanır.
pub struct HybridKeypair {
    pub kyber_public: Vec<u8>,
    pub kyber_secret: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub x25519_secret: [u8; 32],
}

impl Drop for HybridKeypair {
    fn drop(&mut self) {
        crypto::secure_zero(self.kyber_secret.as_mut_slice());
        crypto::secure_zero(&mut self.x25519_secret);
    }
}

pub fn generate_hybrid_keypair() -> Result<HybridKeypair> {
    let kp = generate_keypair()?;
    let xsk = StaticSecret::random_from_rng(rand_core_compat::OsRngShim);
    let xpk = XPublicKey::from(&xsk);
    Ok(HybridKeypair {
        kyber_public: kp.public_key.clone(),
        kyber_secret: kp.secret_key.clone(),
        x25519_public: xpk.to_bytes(),
        x25519_secret: xsk.to_bytes(),
    })
}

/// İki paylaşılan gizliliği (Kyber + X25519) tek 32 baytlık AES anahtarına birleştirir.
/// HKDF-SHA256 ile: en az bir bileşen güvende kaldığı sürece çıktı sözde-rastgele kalır
/// (IETF hibrit-KEM taslaklarındaki "birleştirici" ilkesiyle aynı).
fn combine_hybrid_secret(kyber_ss: &[u8], x25519_ss: &[u8; 32]) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(kyber_ss.len() + 32);
    ikm.extend_from_slice(kyber_ss);
    ikm.extend_from_slice(x25519_ss);
    let okm = crypto::hkdf_expand(&ikm, b"kaotik-hybrid-kem-v1", 32, None)?;
    crypto::secure_zero(&mut ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Ok(out)
}

/// Encapsulate: hibrit alıcı public anahtarlarına karşı. Döner: (aes_key, kyber_ct, x25519_ephemeral_pk).
pub fn hybrid_encapsulate(
    kyber_public: &[u8],
    x25519_public: &[u8; 32],
) -> Result<([u8; 32], Vec<u8>, [u8; 32])> {
    let (mut kyber_ss, kyber_ct) = encapsulate(kyber_public)?;
    let esk = EphemeralSecret::random_from_rng(rand_core_compat::OsRngShim);
    let epk = XPublicKey::from(&esk);
    let recipient_xpk = XPublicKey::from(*x25519_public);
    let mut x25519_ss = esk.diffie_hellman(&recipient_xpk).to_bytes();
    let aes_key = combine_hybrid_secret(&kyber_ss, &x25519_ss)?;
    crypto::secure_zero(kyber_ss.as_mut_slice());
    crypto::secure_zero(&mut x25519_ss);
    Ok((aes_key, kyber_ct, epk.to_bytes()))
}

/// Decapsulate: hibrit gizli anahtarlarla. `x25519_ephemeral_pk` gönderenin geçici public anahtarıdır.
pub fn hybrid_decapsulate(
    kyber_ciphertext: &[u8],
    kyber_secret: &[u8],
    x25519_secret: &[u8; 32],
    x25519_ephemeral_pk: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut kyber_ss = decapsulate(kyber_ciphertext, kyber_secret)?;
    let xsk = StaticSecret::from(*x25519_secret);
    let epk = XPublicKey::from(*x25519_ephemeral_pk);
    let mut x25519_ss = xsk.diffie_hellman(&epk).to_bytes();
    let aes_key = combine_hybrid_secret(&kyber_ss, &x25519_ss)?;
    crypto::secure_zero(kyber_ss.as_mut_slice());
    crypto::secure_zero(&mut x25519_ss);
    Ok(aes_key)
}

/// `x25519-dalek` 2.x, RNG'yi `rand_core` traiti üzerinden ister; ekstra `rand`/`rand_core`
/// bağımlılığı eklememek için `getrandom` tabanlı minimal bir uyum katmanı.
mod rand_core_compat {
    pub struct OsRngShim;

    impl rand_core::RngCore for OsRngShim {
        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.fill_bytes(&mut buf);
            u32::from_le_bytes(buf)
        }
        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            getrandom::getrandom(dest).expect("OS RNG failure");
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for OsRngShim {}
}
