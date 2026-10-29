#![no_main]
//! Rastgele açık anahtar/özet/imza ile verify asla panik etmemeli;
//! girdiden türetilen tohumla atılan imza her zaman doğrulanmalı.
use kaotik::sign::{self, PUBLIC_LEN, SIGNATURE_LEN};
use libfuzzer_sys::fuzz_target;

/// `data`yı tam `n` bayta keser veya sıfırla doldurur (uzunluk kontrollerini geçmek için).
fn fit(data: &[u8], n: usize) -> Vec<u8> {
    let mut v = data[..data.len().min(n)].to_vec();
    v.resize(n, 0);
    v
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + 32 + 64 {
        return;
    }
    let (sel, rest) = (data[0], &data[1..]);
    let seed: [u8; 32] = rest[..32].try_into().unwrap();
    let digest: [u8; 64] = rest[32..96].try_into().unwrap();
    let tail = &rest[96..];
    match sel % 3 {
        // Tamamen rastgele bayt dizileri (çoğunlukla uzunluk hatası).
        0 => {
            let (p, s) = tail.split_at(tail.len() / 2);
            let _ = sign::verify(p, &digest, s);
        }
        // Doğru uzunlukta rastgele anahtar + imza: ayrıştırıcıların derinine iner.
        1 => {
            let p = fit(tail, PUBLIC_LEN);
            let s = fit(tail.get(PUBLIC_LEN.min(tail.len())..).unwrap_or(&[]), SIGNATURE_LEN);
            let _ = sign::verify(&p, &digest, &s);
        }
        // Diferansiyel: gerçek anahtar; geçerli imza true, bozulmuş imza false olmalı.
        _ => {
            let pk = sign::public_key(&seed);
            let sig = sign::sign(&seed, &digest);
            assert!(sign::verify(&pk, &digest, &sig), "valid signature rejected");
            if let Some(&b) = tail.first() {
                let mut bad = sig.clone();
                let i = (b as usize * 31 + tail.len()) % bad.len();
                bad[i] ^= 1 | b;
                assert!(!sign::verify(&pk, &digest, &bad), "tampered signature accepted");
            }
        }
    }
});
