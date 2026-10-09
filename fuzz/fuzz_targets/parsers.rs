//! Anahtar/paket ayrıştırıcıları ve doğrulayıcılar rastgele baytlarda panik yapmamalı.
#![no_main]
use kaotik::hybrid::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = HybridKemPublicKey::from_bytes(data);
    if let Ok(sk) = HybridKemSecretKey::from_bytes(data) {
        let _ = sk.decapsulate(data);
    }
    if let Ok(vk) = HybridVerifyingKey::from_bytes(data) {
        assert!(!vk.verify(b"m", b"", data));
    }
    let _ = kaotik::ratchet::PrekeyBundle::from_bytes(data);
    let _ = kaotik::ratchet::Session::import(&[1u8; 32], data);
    let _ = kaotik::hashsig::SlhVerifyingKey::from_bytes(data);
    let _ = kaotik::passhash::verify_password("p", &String::from_utf8_lossy(data));
});
