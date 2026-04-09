//! C FFI: `cargo build --features ffi` ile derlenir. Python/Go/JS gibi dillerden çağrılabilir.
//! Örnek: `kaotik_encrypt_aes(plain_ptr, plain_len, out_ptr, out_len, password_ptr, password_len)`
#![cfg(feature = "ffi")]

use std::io::Cursor;
use std::slice;

/// 0 = başarı, 1 = hata (genel), 2 = format/parola hatası
#[no_mangle]
pub extern "C" fn kaotik_encrypt_aes(
    plain_ptr: *const u8,
    plain_len: usize,
    out_ptr: *mut u8,
    out_len: *mut usize,
    password_ptr: *const u8,
    password_len: usize,
) -> i32 {
    if plain_ptr.is_null() || out_ptr.is_null() || out_len.is_null() || password_ptr.is_null() {
        return 1;
    }
    let plain = unsafe { slice::from_raw_parts(plain_ptr, plain_len) };
    let password = match std::str::from_utf8(unsafe { slice::from_raw_parts(password_ptr, password_len) }) {
        Ok(s) => s,
        _ => return 2,
    };
    let mut cipher = Vec::new();
    match kaotik::encrypt_aes(Cursor::new(plain), &mut cipher, password) {
        Ok(()) => {
            let len = cipher.len();
            if len <= (usize::MAX) {
                unsafe {
                    std::ptr::copy_nonoverlapping(cipher.as_ptr(), out_ptr, len);
                    *out_len = len;
                }
                0
            } else {
                1
            }
        }
        Err(_) => 2,
    }
}

/// AES decrypt: cipher_ptr/cipher_len → plain_ptr'ye yazar, *plain_len güncellenir. 0=OK, 1=hata, 2=format/parola
#[no_mangle]
pub extern "C" fn kaotik_decrypt_aes(
    cipher_ptr: *const u8,
    cipher_len: usize,
    plain_ptr: *mut u8,
    plain_len: *mut usize,
    password_ptr: *const u8,
    password_len: usize,
) -> i32 {
    if cipher_ptr.is_null() || plain_ptr.is_null() || plain_len.is_null() || password_ptr.is_null() {
        return 1;
    }
    let cipher = unsafe { slice::from_raw_parts(cipher_ptr, cipher_len) };
    let password = match std::str::from_utf8(unsafe { slice::from_raw_parts(password_ptr, password_len) }) {
        Ok(s) => s,
        _ => return 2,
    };
    let mut plain = Vec::new();
    match kaotik::decrypt_aes(Cursor::new(cipher), &mut plain, password) {
        Ok(()) => {
            let len = plain.len();
            unsafe {
                std::ptr::copy_nonoverlapping(plain.as_ptr(), plain_ptr, len);
                *plain_len = len;
            }
            crate::crypto::secure_zero(plain.as_mut_slice());
            0
        }
        Err(_) => 2,
    }
}

/// Doğrulama: 0 = geçerli yapı, 1 = hata
#[no_mangle]
pub extern "C" fn kaotik_verify_file(data_ptr: *const u8, data_len: usize) -> i32 {
    if data_ptr.is_null() {
        return 1;
    }
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    match kaotik::verify_file(Cursor::new(data)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
