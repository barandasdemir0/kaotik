#![no_main]
//! Hibrit KEM: rastgele şifreli metinle decapsulate panik etmemeli;
//! tohumdan türetilen anahtar çiftinde encapsulate→decapsulate aynı sırrı vermeli.
use kaotik::hybrid_kem::{self, CIPHERTEXT_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let seed: [u8; 32] = data[1..33].try_into().unwrap();
    let ct = &data[33..];
    if data[0] & 1 == 0 {
        let _ = hybrid_kem::decapsulate(&seed, ct);
        // Doğru uzunluğa getirilmiş sürüm de denenir (ML-KEM / X25519 yoluna iner).
        let mut fixed = ct[..ct.len().min(CIPHERTEXT_LEN)].to_vec();
        fixed.resize(CIPHERTEXT_LEN, 0);
        let _ = hybrid_kem::decapsulate(&seed, &fixed);
    } else {
        let pk = hybrid_kem::public_key(&seed).expect("public_key");
        let (c, k1) = hybrid_kem::encapsulate(&pk).expect("encapsulate");
        let k2 = hybrid_kem::decapsulate(&seed, &c).expect("decapsulate");
        assert_eq!(&k1[..], &k2[..], "KEM shared secret mismatch");
    }
});
