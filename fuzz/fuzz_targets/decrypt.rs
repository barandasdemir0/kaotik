#![no_main]
//! Tüm çözme yolları: bozuk/sahte şifreli dosya ve anahtar dosyaları yalnızca hata döndürmeli.
//! İlk bayt hangi modun deneneceğini seçer; geri kalanı şifreli dosya olarak verilir.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const PW: &str = "FuzzPassword123!@#";

fuzz_target!(init: std::env::set_var("KAOTIK_FUZZ_CHEAP_KDF", "1"), |data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    // Anahtar dosyası olarak da aynı girdinin bir dilimi kullanılır.
    let (file, key) = rest.split_at(rest.len() / 2);
    let mut out = Vec::new();
    let _ = match sel % 5 {
        0 => kaotik::decrypt_kaotik(Cursor::new(rest), &mut out, PW),
        1 => kaotik::decrypt_aes(Cursor::new(rest), &mut out, PW),
        2 => kaotik::decrypt_kyber(Cursor::new(file), &mut out, PW, &mut Cursor::new(key)),
        3 => kaotik::decrypt_from_recipient(Cursor::new(file), &mut out, PW, &mut Cursor::new(key), None).map(|_| ()),
        _ => kaotik::verify_file(Cursor::new(rest)),
    };
});
