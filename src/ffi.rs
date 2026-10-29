//! C FFI: `cargo build --features ffi` ile derlenir. Python/Go/JS gibi dillerden çağrılabilir.
//! Örnek: `kaotik_encrypt_aes(plain_ptr, plain_len, out_ptr, out_len, password_ptr, password_len)`
#![cfg(feature = "ffi")]
// C ABI: işaretçilerin geçerliliği çağıranın sorumluluğu (extern "C" sözleşmesi).
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::io::Cursor;
use std::slice;

/// 0 = başarı, 1 = hata (genel), 2 = format/parola hatası, 3 = çıktı tamponu küçük.
/// `*out_len` girişte tampon kapasitesidir; çıkışta yazılan (veya 3 ise gereken) bayt sayısı.
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
    let password =
        match std::str::from_utf8(unsafe { slice::from_raw_parts(password_ptr, password_len) }) {
            Ok(s) => s,
            _ => return 2,
        };
    let mut cipher = Vec::new();
    match crate::encrypt_aes(Cursor::new(plain), &mut cipher, password) {
        Ok(()) => {
            let len = cipher.len();
            unsafe {
                if len > *out_len {
                    *out_len = len;
                    return 3;
                }
                std::ptr::copy_nonoverlapping(cipher.as_ptr(), out_ptr, len);
                *out_len = len;
            }
            0
        }
        Err(_) => 2,
    }
}

/// AES decrypt: cipher_ptr/cipher_len → plain_ptr'ye yazar. `*plain_len` girişte kapasite, çıkışta yazılan boyut.
/// 0=OK, 1=hata, 2=format/parola, 3=tampon küçük (gereken boyut `*plain_len`'e yazılır)
#[no_mangle]
pub extern "C" fn kaotik_decrypt_aes(
    cipher_ptr: *const u8,
    cipher_len: usize,
    plain_ptr: *mut u8,
    plain_len: *mut usize,
    password_ptr: *const u8,
    password_len: usize,
) -> i32 {
    if cipher_ptr.is_null() || plain_ptr.is_null() || plain_len.is_null() || password_ptr.is_null()
    {
        return 1;
    }
    let cipher = unsafe { slice::from_raw_parts(cipher_ptr, cipher_len) };
    let password =
        match std::str::from_utf8(unsafe { slice::from_raw_parts(password_ptr, password_len) }) {
            Ok(s) => s,
            _ => return 2,
        };
    let mut plain = Vec::new();
    match crate::decrypt_aes(Cursor::new(cipher), &mut plain, password) {
        Ok(()) => {
            let len = plain.len();
            let fits = unsafe { len <= *plain_len };
            unsafe {
                if fits {
                    std::ptr::copy_nonoverlapping(plain.as_ptr(), plain_ptr, len);
                }
                *plain_len = len;
            }
            crate::crypto::secure_zero(plain.as_mut_slice());
            if fits {
                0
            } else {
                3
            }
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
    match crate::verify_file(Cursor::new(data)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_output_buffer_is_refused_not_overflowed() {
        let pw = b"Kx7#mQv2!Lr9$Wz4";
        let plain = [7u8; 100];
        let mut out = [0u8; 64];
        let mut len = out.len();
        let rc = kaotik_encrypt_aes(
            plain.as_ptr(),
            plain.len(),
            out.as_mut_ptr(),
            &mut len,
            pw.as_ptr(),
            pw.len(),
        );
        assert_eq!(rc, 3);
        assert!(len > 64);
        let mut big = vec![0u8; len];
        let rc = kaotik_encrypt_aes(
            plain.as_ptr(),
            plain.len(),
            big.as_mut_ptr(),
            &mut len,
            pw.as_ptr(),
            pw.len(),
        );
        assert_eq!(rc, 0);
        let mut dec = [0u8; 10];
        let mut dlen = dec.len();
        assert_eq!(
            kaotik_decrypt_aes(
                big.as_ptr(),
                len,
                dec.as_mut_ptr(),
                &mut dlen,
                pw.as_ptr(),
                pw.len()
            ),
            3
        );
        assert_eq!(dlen, 100);
    }
}
