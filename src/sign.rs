//! Hibrit imza: ML-DSA-65 (FIPS 204) + Ed25519.
//!
//! İkisi birden doğrulanmak zorunda; böylece sahtecilik için hem kuantum-sonrası
//! hem klasik şemanın kırılması gerekir. Anahtarlar KEM kimliğiyle aynı 32 baytlık
//! tohumdan HKDF ile ayrı etiketlerle türetilir, ayrı bir gizli saklamaya gerek kalmaz.

use ed25519_dalek::Signer;
use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Signature, VerifyingKey,
};
use sha2::Sha256;
use zeroize::Zeroizing;

const MLDSA_PUB: usize = 1952;
const MLDSA_SIG: usize = 3309;
const ED_PUB: usize = 32;
const ED_SIG: usize = 64;

pub const PUBLIC_LEN: usize = MLDSA_PUB + ED_PUB;
pub const SIGNATURE_LEN: usize = MLDSA_SIG + ED_SIG;

/// Bağlam dizesi imzayı bu kullanıma bağlar; başka protokoldeki imza burada geçmez.
const CONTEXT: &[u8] = b"kaotik-v8-file-signature";

/// Ayrı etiketler iki şemanın anahtarlarını birbirinden bağımsız kılar.
fn derive(seed: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, seed)
        .expand(info, out.as_mut())
        .expect("32 bayt HKDF sınırı içinde");
    out
}

fn mldsa_key(seed: &[u8; 32]) -> ExpandedSigningKey<MlDsa65> {
    let s = derive(seed, b"kaotik-sig-mldsa65");
    ExpandedSigningKey::<MlDsa65>::from_seed(&(*s).into())
}

fn ed_key(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let s = derive(seed, b"kaotik-sig-ed25519");
    ed25519_dalek::SigningKey::from_bytes(&s)
}

/// Ed25519'un bağlam parametresi yok; bağlamı mesajın önüne ekleyerek aynı bağlamı sağlıyoruz.
fn ed_message(digest: &[u8; 64]) -> Vec<u8> {
    let mut m = Vec::with_capacity(CONTEXT.len() + digest.len());
    m.extend_from_slice(CONTEXT);
    m.extend_from_slice(digest);
    m
}

/// Public signing key bytes: ML-DSA-65 vk || Ed25519 vk.
pub fn public_key(seed: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_LEN);
    out.extend_from_slice(&mldsa_key(seed).verifying_key().encode());
    out.extend_from_slice(&ed_key(seed).verifying_key().to_bytes());
    out
}

/// Signs a 64-byte digest (caller hashes the message with SHA-512). Context string binds the use.
pub fn sign(seed: &[u8; 32], digest: &[u8; 64]) -> Vec<u8> {
    // Deterministik imza: RNG hatası veya zayıf rastgelelik gizli anahtarı sızdıramaz.
    let pq = mldsa_key(seed)
        .sign_deterministic(digest, CONTEXT)
        .expect("bağlam 255 bayttan kısa");
    let ed = ed_key(seed).sign(&ed_message(digest));
    let mut out = Vec::with_capacity(SIGNATURE_LEN);
    out.extend_from_slice(&pq.encode());
    out.extend_from_slice(&ed.to_bytes());
    out
}

/// True only if BOTH signatures are valid for this public key and digest.
pub fn verify(public: &[u8], digest: &[u8; 64], signature: &[u8]) -> bool {
    // Uzunluklar saldırgan kontrolünde; panik yerine false dönmeli.
    if public.len() != PUBLIC_LEN || signature.len() != SIGNATURE_LEN {
        return false;
    }
    let (pq_pub, ed_pub) = public.split_at(MLDSA_PUB);
    let (pq_sig, ed_sig) = signature.split_at(MLDSA_SIG);

    let pq_ok = (|| {
        let vk = VerifyingKey::<MlDsa65>::decode(
            &EncodedVerifyingKey::<MlDsa65>::try_from(pq_pub).ok()?,
        );
        let sig =
            Signature::<MlDsa65>::decode(&EncodedSignature::<MlDsa65>::try_from(pq_sig).ok()?)?;
        Some(vk.verify_with_context(digest, CONTEXT, &sig))
    })()
    .unwrap_or(false);

    let ed_ok = (|| {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(ed_pub.try_into().ok()?).ok()?;
        let sig = ed25519_dalek::Signature::from_bytes(ed_sig.try_into().ok()?);
        // verify_strict: düşük mertebeli/değiştirilebilir imzaları reddeder.
        Some(vk.verify_strict(&ed_message(digest), &sig).is_ok())
    })()
    .unwrap_or(false);

    // Kısa devre yok: iki kontrol de her zaman çalışır.
    pq_ok & ed_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    const SEED: [u8; 32] = [7u8; 32];
    const DIGEST: [u8; 64] = [0x42u8; 64];

    #[test]
    fn sizes_and_roundtrip() {
        let pk = public_key(&SEED);
        let sig = sign(&SEED, &DIGEST);
        assert_eq!(pk.len(), PUBLIC_LEN);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&pk, &DIGEST, &sig));
    }

    #[test]
    fn wrong_digest_fails() {
        let sig = sign(&SEED, &DIGEST);
        let mut d = DIGEST;
        d[0] ^= 1;
        assert!(!verify(&public_key(&SEED), &d, &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let sig = sign(&SEED, &DIGEST);
        assert!(!verify(&public_key(&[8u8; 32]), &DIGEST, &sig));
    }

    #[test]
    fn corrupt_mldsa_part_fails() {
        let mut sig = sign(&SEED, &DIGEST);
        sig[10] ^= 1;
        assert!(!verify(&public_key(&SEED), &DIGEST, &sig));
    }

    #[test]
    fn corrupt_ed25519_part_fails() {
        let mut sig = sign(&SEED, &DIGEST);
        sig[MLDSA_SIG + 5] ^= 1;
        assert!(!verify(&public_key(&SEED), &DIGEST, &sig));
    }

    #[test]
    fn bad_lengths_return_false() {
        let pk = public_key(&SEED);
        let sig = sign(&SEED, &DIGEST);
        assert!(!verify(&pk, &DIGEST, &sig[..sig.len() - 1]));
        let mut long = sig.clone();
        long.push(0);
        assert!(!verify(&pk, &DIGEST, &long));
        assert!(!verify(&pk[..pk.len() - 1], &DIGEST, &sig));
        let mut longpk = pk.clone();
        longpk.push(0);
        assert!(!verify(&longpk, &DIGEST, &sig));
        assert!(!verify(&[], &DIGEST, &[]));
        assert!(!verify(
            &[0xff; PUBLIC_LEN],
            &DIGEST,
            &[0xff; SIGNATURE_LEN]
        ));
    }

    #[test]
    fn public_key_is_deterministic() {
        let pk = public_key(&SEED);
        assert_eq!(pk, public_key(&SEED));
        let h = Sha256::digest(&pk);
        let hex: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "086211c7ddbc2f76");
    }
}
