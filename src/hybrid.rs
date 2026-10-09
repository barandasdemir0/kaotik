//! Hibrit (klasik + kuantum sonrası) kripto katmanı — uygulamalara gömülmek için.
//!
//! Tasarım ilkesi: **iki bağımsız matematik problemine birden** dayanmak. Saldırganın
//! hem eliptik eğriyi (X25519 / Ed25519) **hem de** kafes problemini (ML-KEM-1024 /
//! ML-DSA-87, NIST FIPS 203/204, en yüksek güvenlik kategorisi 5) kırması gerekir.
//! Biri ileride kırılsa bile diğeri korumaya devam eder.
//!
//! | İşlev | Algoritma |
//! |-------|-----------|
//! | Simetrik şifreleme (`seal`/`open`) | XChaCha20-Poly1305 (256-bit anahtar, 192-bit rastgele nonce) |
//! | Anahtar anlaşması (`HybridKem*`) | X25519 + ML-KEM-1024, X-Wing tarzı birleştirici (HKDF-SHA512) |
//! | İmza (`HybridSign*`) | Ed25519 (strict) + ML-DSA-87 (hedged); **ikisi de** geçerli olmalı |
//! | Açık anahtarla şifreleme (`seal_to`/`open_from`) | Hibrit KEM + XChaCha20-Poly1305, KEM şifreli metni AAD'ye bağlı |
//!
//! Tüm gizli anahtarlar `Zeroize` ile bellekten silinir; serileştirme sabit uzunluktadır.

use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use ml_dsa::MlDsa87;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem1024, TryKeyInit};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Protokol/suite etiketi; tüm türetmelerde alan ayırıcı (domain separation) olarak kullanılır.
pub const SUITE: &[u8] = b"KAOTIK-HYBRID-v1/X25519+MLKEM1024/Ed25519+MLDSA87/XChaCha20Poly1305/HKDF-SHA512";

pub const KEY_LEN: usize = 32;
pub const SEAL_VERSION: u8 = 1;
const XNONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// `seal` çıktısı ek yükü: sürüm + nonce + etiket.
pub const SEAL_OVERHEAD: usize = 1 + XNONCE_LEN + TAG_LEN;

const MLKEM_SEED_LEN: usize = 64;
const MLKEM_EK_LEN: usize = 1568;
const MLKEM_CT_LEN: usize = 1568;
const MLDSA_VK_LEN: usize = 2592;
const MLDSA_SIG_LEN: usize = 4627;

pub const KEM_PUBLIC_LEN: usize = 32 + MLKEM_EK_LEN;
pub const KEM_SECRET_LEN: usize = 32 + MLKEM_SEED_LEN;
pub const KEM_CIPHERTEXT_LEN: usize = 32 + MLKEM_CT_LEN;
pub const SIGN_PUBLIC_LEN: usize = 32 + MLDSA_VK_LEN;
pub const SIGN_SECRET_LEN: usize = 32 + 32;
pub const SIGNATURE_LEN: usize = 64 + MLDSA_SIG_LEN;

fn crypto_err() -> Error {
    Error::Crypto("Decryption failed".into())
}

fn random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut buf = Zeroizing::new([0u8; N]);
    random_bytes(&mut buf[..])?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Simetrik: seal / open
// ---------------------------------------------------------------------------

/// Yeni rastgele 256-bit simetrik anahtar.
pub fn generate_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    random_array::<KEY_LEN>()
}

/// Ham anahtarla kimlik doğrulamalı şifreleme. `aad` şifrelenmez ama doğrulanır
/// (ör. sohbet id'si, gönderen, mesaj sırası). Çıktı: `ver(1) || nonce(24) || ct || tag(16)`.
///
/// Parola türetme veya yapay bekleme yoktur; mesaj başına mikro saniyeler mertebesindedir.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_array::<XNONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut full_aad = Vec::with_capacity(1 + aad.len());
    full_aad.push(SEAL_VERSION);
    full_aad.extend_from_slice(aad);
    let ct = cipher
        .encrypt(&XNonce::try_from(&nonce[..]).expect("24"), Payload { msg: plaintext, aad: &full_aad })
        .map_err(|_| Error::Crypto("Encryption failed".into()))?;
    let mut out = Vec::with_capacity(SEAL_OVERHEAD + plaintext.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&nonce[..]);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// `seal` çıktısını açar. Yanlış anahtar, değiştirilmiş veri veya farklı `aad` → hata.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < SEAL_OVERHEAD || sealed[0] != SEAL_VERSION {
        return Err(crypto_err());
    }
    let nonce = &XNonce::try_from(&sealed[1..1 + XNONCE_LEN]).map_err(|_| crypto_err())?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut full_aad = Vec::with_capacity(1 + aad.len());
    full_aad.push(SEAL_VERSION);
    full_aad.extend_from_slice(aad);
    cipher
        .decrypt(nonce, Payload { msg: &sealed[1 + XNONCE_LEN..], aad: &full_aad })
        .map(Zeroizing::new)
        .map_err(|_| crypto_err())
}

// ---------------------------------------------------------------------------
// Hibrit KEM: X25519 + ML-KEM-1024
// ---------------------------------------------------------------------------

/// Hibrit KEM gizli anahtarı (X25519 skaler + ML-KEM-1024 tohumu). Bellekten otomatik silinir.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemSecretKey {
    x25519: [u8; 32],
    mlkem_seed: [u8; MLKEM_SEED_LEN],
}

/// Hibrit KEM açık anahtarı; karşı tarafa paylaşılır.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridKemPublicKey {
    x25519: [u8; 32],
    mlkem: Vec<u8>,
}

fn mlkem_dk(seed: &[u8; MLKEM_SEED_LEN]) -> ml_kem::DecapsulationKey<MlKem1024> {
    let seed: ml_kem::Seed = (*seed).into();
    ml_kem::DecapsulationKey::<MlKem1024>::from_seed(seed)
}

impl HybridKemSecretKey {
    pub fn generate() -> Result<Self> {
        let x = random_array::<32>()?;
        let s = random_array::<MLKEM_SEED_LEN>()?;
        Ok(Self { x25519: *x, mlkem_seed: *s })
    }

    pub fn public_key(&self) -> HybridKemPublicKey {
        let x_pub = x25519_dalek::x25519(self.x25519, x25519_dalek::X25519_BASEPOINT_BYTES);
        let ek = mlkem_dk(&self.mlkem_seed).encapsulation_key().to_bytes();
        HybridKemPublicKey { x25519: x_pub, mlkem: ek.to_vec() }
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(KEM_SECRET_LEN));
        v.extend_from_slice(&self.x25519);
        v.extend_from_slice(&self.mlkem_seed);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != KEM_SECRET_LEN {
            return Err(Error::Format("Invalid KEM secret key length".into()));
        }
        let mut sk = Self { x25519: [0; 32], mlkem_seed: [0; MLKEM_SEED_LEN] };
        sk.x25519.copy_from_slice(&b[..32]);
        sk.mlkem_seed.copy_from_slice(&b[32..]);
        Ok(sk)
    }

    /// Kapsüllenmiş anahtarı açar ve ortak 32 baytlık sırrı döndürür.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        if ct.len() != KEM_CIPHERTEXT_LEN {
            return Err(crypto_err());
        }
        let (ct_x, ct_m) = ct.split_at(32);
        let mut ct_x_arr = [0u8; 32];
        ct_x_arr.copy_from_slice(ct_x);
        let ss_x = Zeroizing::new(x25519_dalek::x25519(self.x25519, ct_x_arr));
        if bool::from(ss_x.ct_eq(&[0u8; 32])) {
            return Err(crypto_err());
        }
        let ss_m = mlkem_dk(&self.mlkem_seed)
            .decapsulate_slice(ct_m)
            .map_err(|_| crypto_err())?;
        let pk = self.public_key();
        Ok(combine(&ss_m[..], &ss_x[..], ct_x, &pk.x25519, ct_m, &pk.mlkem))
    }
}

impl HybridKemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(KEM_PUBLIC_LEN);
        v.extend_from_slice(&self.x25519);
        v.extend_from_slice(&self.mlkem);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != KEM_PUBLIC_LEN {
            return Err(Error::Format("Invalid KEM public key length".into()));
        }
        // ML-KEM açık anahtarını FIPS 203 modulus kontrolüyle doğrula.
        ml_kem::EncapsulationKey::<MlKem1024>::new_from_slice(&b[32..])
            .map_err(|_| Error::Format("Invalid ML-KEM public key".into()))?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        Ok(Self { x25519: x, mlkem: b[32..].to_vec() })
    }

    /// Bu açık anahtara ortak sır kapsüller: `(ciphertext, shared_secret)`.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let eph = random_array::<32>()?;
        let ct_x = x25519_dalek::x25519(*eph, x25519_dalek::X25519_BASEPOINT_BYTES);
        let ss_x = Zeroizing::new(x25519_dalek::x25519(*eph, self.x25519));
        if bool::from(ss_x.ct_eq(&[0u8; 32])) {
            return Err(Error::Crypto("Invalid X25519 public key".into()));
        }
        let ek = ml_kem::EncapsulationKey::<MlKem1024>::new_from_slice(&self.mlkem)
            .map_err(|_| Error::Format("Invalid ML-KEM public key".into()))?;
        let (ct_m, ss_m) = ek.encapsulate();
        let ss = combine(&ss_m[..], &ss_x[..], &ct_x, &self.x25519, &ct_m[..], &self.mlkem);
        let mut ct = Vec::with_capacity(KEM_CIPHERTEXT_LEN);
        ct.extend_from_slice(&ct_x);
        ct.extend_from_slice(&ct_m[..]);
        Ok((ct, ss))
    }
}

/// X-Wing tarzı birleştirici: her iki sır + tüm şifreli metin/açık anahtar transkripti.
/// Bileşenlerden biri kırılsa bile çıktı diğerinin gücünü korur.
fn combine(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8], ct_m: &[u8], pk_m: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(ss_x);
    let mut h = Sha512::new();
    for part in [ct_x, pk_x, ct_m, pk_m] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    let transcript = h.finalize();
    let hk = Hkdf::<Sha512>::new(Some(SUITE), &ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&transcript, &mut out[..]).expect("32 <= 255*64");
    out
}

// ---------------------------------------------------------------------------
// Açık anahtarla şifreleme (HPKE benzeri, tek atımlık)
// ---------------------------------------------------------------------------

/// Alıcının açık anahtarına şifreler. Çıktı: `kem_ct || seal(...)`.
pub fn seal_to(recipient: &HybridKemPublicKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let (kem_ct, ss) = recipient.encapsulate()?;
    let key = derive_subkey(&ss[..], b"seal_to", &kem_ct);
    let mut bound_aad = kem_ct.clone();
    bound_aad.extend_from_slice(aad);
    let body = seal(&key, plaintext, &bound_aad)?;
    let mut out = kem_ct;
    out.extend_from_slice(&body);
    Ok(out)
}

/// `seal_to` çıktısını alıcının gizli anahtarıyla açar.
pub fn open_from(sk: &HybridKemSecretKey, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < KEM_CIPHERTEXT_LEN + SEAL_OVERHEAD {
        return Err(crypto_err());
    }
    let (kem_ct, body) = sealed.split_at(KEM_CIPHERTEXT_LEN);
    let ss = sk.decapsulate(kem_ct)?;
    let key = derive_subkey(&ss[..], b"seal_to", kem_ct);
    let mut bound_aad = kem_ct.to_vec();
    bound_aad.extend_from_slice(aad);
    open(&key, body, &bound_aad)
}

/// Ortak sırdan amaç-ayrık alt anahtar türetir (ör. sohbet gönderme/alma anahtarları).
pub fn derive_subkey(secret: &[u8], label: &[u8], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(SUITE), secret);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&[&(label.len() as u32).to_be_bytes(), label, context], &mut out[..])
        .expect("32 <= 255*64");
    out
}

// ---------------------------------------------------------------------------
// Hibrit imza: Ed25519 + ML-DSA-87
// ---------------------------------------------------------------------------

/// Hibrit imza gizli anahtarı (iki 32 baytlık tohum).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSigningKey {
    ed: [u8; 32],
    mldsa: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    ed: [u8; 32],
    mldsa: Vec<u8>,
}

fn mldsa_sk(seed: &[u8; 32]) -> ml_dsa::SigningKey<MlDsa87> {
    ml_dsa::SigningKey::<MlDsa87>::from_seed(&(*seed).into())
}

impl HybridSigningKey {
    pub fn generate() -> Result<Self> {
        let a = random_array::<32>()?;
        let b = random_array::<32>()?;
        Ok(Self { ed: *a, mldsa: *b })
    }

    pub fn verifying_key(&self) -> HybridVerifyingKey {
        let ed = ed25519_dalek::SigningKey::from_bytes(&self.ed).verifying_key().to_bytes();
        let vk = mldsa_sk(&self.mldsa).expanded_key().verifying_key().encode();
        HybridVerifyingKey { ed, mldsa: vk.to_vec() }
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(SIGN_SECRET_LEN));
        v.extend_from_slice(&self.ed);
        v.extend_from_slice(&self.mldsa);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != SIGN_SECRET_LEN {
            return Err(Error::Format("Invalid signing key length".into()));
        }
        let mut sk = Self { ed: [0; 32], mldsa: [0; 32] };
        sk.ed.copy_from_slice(&b[..32]);
        sk.mldsa.copy_from_slice(&b[32..]);
        Ok(sk)
    }

    /// `ctx` (≤255 bayt) imzayı bir amaca bağlar (ör. b"chat-msg"); doğrulamada aynısı verilmeli.
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        if ctx.len() > 255 {
            return Err(Error::Format("Context too long".into()));
        }
        let bound = bind_message(msg, ctx);
        let ed_sig = ed25519_dalek::SigningKey::from_bytes(&self.ed).sign_prehashed_free(&bound);
        let rnd = random_array::<32>()?;
        let ctx_hdr = [0u8, ctx.len() as u8];
        let ml_sig = mldsa_sk(&self.mldsa)
            .expanded_key()
            .sign_internal(&[&ctx_hdr, ctx, &bound], &(*rnd).into())
            .encode();
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&ed_sig);
        out.extend_from_slice(&ml_sig);
        Ok(out)
    }
}

impl HybridVerifyingKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIGN_PUBLIC_LEN);
        v.extend_from_slice(&self.ed);
        v.extend_from_slice(&self.mldsa);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != SIGN_PUBLIC_LEN {
            return Err(Error::Format("Invalid verifying key length".into()));
        }
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&b[..32]);
        ed25519_dalek::VerifyingKey::from_bytes(&ed)
            .map_err(|_| Error::Format("Invalid Ed25519 key".into()))?;
        Ok(Self { ed, mldsa: b[32..].to_vec() })
    }

    /// İmza **yalnızca** Ed25519 ve ML-DSA-87 imzalarının ikisi de geçerliyse kabul edilir.
    pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SIGNATURE_LEN || ctx.len() > 255 {
            return false;
        }
        let bound = bind_message(msg, ctx);
        let ed_ok = (|| {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.ed).ok()?;
            let s = ed25519_dalek::Signature::from_slice(&sig[..64]).ok()?;
            vk.verify_strict(&bound, &s).ok()
        })()
        .is_some();
        let ml_ok = (|| {
            let vk_enc = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(&self.mldsa[..]).ok()?;
            let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&vk_enc);
            let sig_enc = ml_dsa::EncodedSignature::<MlDsa87>::try_from(&sig[64..]).ok()?;
            let s = ml_dsa::Signature::<MlDsa87>::decode(&sig_enc)?;
            vk.verify_with_context(&bound, ctx, &s).then_some(())
        })()
        .is_some();
        ed_ok & ml_ok
    }
}

/// İmzalanan mesajı suite ve bağlamla bağlar; iki imza da aynı bayt dizisini kapsar.
fn bind_message(msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SUITE.len() + 2 + ctx.len() + msg.len());
    v.extend_from_slice(SUITE);
    v.push(ctx.len() as u8);
    v.extend_from_slice(ctx);
    v.extend_from_slice(msg);
    v
}

trait EdSignFree {
    fn sign_prehashed_free(&self, msg: &[u8]) -> [u8; 64];
}
impl EdSignFree for ed25519_dalek::SigningKey {
    fn sign_prehashed_free(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.sign(msg).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let k = generate_key().unwrap();
        let c = seal(&k, b"merhaba", b"chat:42").unwrap();
        assert_eq!(&open(&k, &c, b"chat:42").unwrap()[..], b"merhaba");
        assert!(open(&k, &c, b"chat:43").is_err());
        let mut t = c.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(open(&k, &t, b"chat:42").is_err());
        let k2 = generate_key().unwrap();
        assert!(open(&k2, &c, b"chat:42").is_err());
    }

    #[test]
    fn kem_roundtrip_and_serialization() {
        let sk = HybridKemSecretKey::generate().unwrap();
        let pk = HybridKemPublicKey::from_bytes(&sk.public_key().to_bytes()).unwrap();
        let (ct, ss1) = pk.encapsulate().unwrap();
        assert_eq!(ct.len(), KEM_CIPHERTEXT_LEN);
        let sk2 = HybridKemSecretKey::from_bytes(&sk.to_bytes()).unwrap();
        let ss2 = sk2.decapsulate(&ct).unwrap();
        assert_eq!(*ss1, *ss2);
        // Tampered ciphertext → farklı sır (ML-KEM implicit rejection)
        let mut bad = ct.clone();
        bad[100] ^= 1;
        assert_ne!(*sk.decapsulate(&bad).unwrap(), *ss1);
    }

    #[test]
    fn seal_to_open_from() {
        let sk = HybridKemSecretKey::generate().unwrap();
        let c = seal_to(&sk.public_key(), b"gizli", b"").unwrap();
        assert_eq!(&open_from(&sk, &c, b"").unwrap()[..], b"gizli");
        let other = HybridKemSecretKey::generate().unwrap();
        assert!(open_from(&other, &c, b"").is_err());
    }

    #[test]
    fn hybrid_signature() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = HybridVerifyingKey::from_bytes(&sk.verifying_key().to_bytes()).unwrap();
        let sig = sk.sign(b"mesaj", b"chat").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(vk.verify(b"mesaj", b"chat", &sig));
        assert!(!vk.verify(b"mesaj!", b"chat", &sig));
        assert!(!vk.verify(b"mesaj", b"other", &sig));
        // Tek bileşenin bozulması yeterli olmalı
        let mut s1 = sig.clone();
        s1[0] ^= 1;
        assert!(!vk.verify(b"mesaj", b"chat", &s1));
        let mut s2 = sig.clone();
        s2[100] ^= 1;
        assert!(!vk.verify(b"mesaj", b"chat", &s2));
        let sk2 = HybridSigningKey::from_bytes(&sk.to_bytes()).unwrap();
        assert!(vk.verify(b"x", b"", &sk2.sign(b"x", b"").unwrap()));
    }
}
