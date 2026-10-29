//! Rastgele girdilerle simetrik/akış/kutu açıcılar asla panik yapmamalı ve kabul etmemeli.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [7u8; 32];
    assert!(kaotik::hybrid::open(&key, data, b"").is_err());
    let _ = kaotik::stream::open_stream(&key, b"", data, std::io::sink());
    let _ = kaotik::keystore::params_of(data);
    let _ = kaotik::verify_file(std::io::Cursor::new(data));
    let _ = kaotik::decrypt_aes(std::io::Cursor::new(data), std::io::sink(), "x");
});
