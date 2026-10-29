#![no_main]
//! chaotic2::apply ardından reverse orijinal veriyi geri vermeli.
use libfuzzer_sys::fuzz_target;

const MAX_DATA: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let salt_len = (data[32] as usize) % 64;
    let rest = &data[33..];
    let (salt, plain) = rest.split_at(salt_len.min(rest.len()));
    let plain = &plain[..plain.len().min(MAX_DATA)];
    let mut buf = plain.to_vec();
    kaotik::chaotic2::apply(&mut buf, &key, salt);
    kaotik::chaotic2::reverse(&mut buf, &key, salt);
    assert_eq!(buf, plain, "chaotic2 roundtrip mismatch");
});
