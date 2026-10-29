#![no_main]
//! Format ayrıştırıcıları: herhangi bir bayt dizisi çökme, panik veya sınırsız bellek üretmemeli.
use kaotik::format;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(init: std::env::set_var("KAOTIK_FUZZ_CHEAP_KDF", "1"), |data: &[u8]| {
    let _ = kaotik::verify_file(Cursor::new(data));
    let _ = format::read_encrypted_secret_key(&mut Cursor::new(data));
    let _ = format::read_kyber_payload(&mut Cursor::new(data));
    let _ = format::read_kyber_payload_v6(&mut Cursor::new(data));
    let _ = format::read_aes_stream_start(&mut Cursor::new(data));
    let _ = kaotik::encrypt_to_recipient(Cursor::new(b"x"), Vec::new(), &mut Cursor::new(data), None);
});
