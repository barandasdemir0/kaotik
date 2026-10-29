//! Kurulu bir oturuma rastgele mesaj: panik yok, durum bozulmaz (sonraki gerçek mesaj açılır).
#![no_main]
use kaotik::hybrid::HybridSigningKey;
use kaotik::ratchet::{PrekeyBundle, Session};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static PAIR: OnceLock<(Session, Session)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let (a, b) = PAIR.get_or_init(|| {
        let ai = HybridSigningKey::generate().unwrap();
        let bi = HybridSigningKey::generate().unwrap();
        let (bundle, pk) = PrekeyBundle::new(&bi).unwrap();
        let (a, init) = Session::initiate(&ai, &bundle).unwrap();
        let (b, _) = Session::respond(&bi, &pk, &init).unwrap();
        (a, b)
    });
    let (mut a, mut b) = (a.clone(), b.clone());
    assert!(b.decrypt(data, b"").is_err());
    let m = a.encrypt(b"ok", b"").unwrap();
    assert_eq!(&b.decrypt(&m, b"").unwrap()[..], b"ok");
});
