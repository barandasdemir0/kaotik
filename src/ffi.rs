//! C ABI: `cargo build --release --features ffi` → `libkaotik.so` / `kaotik.dll` / `libkaotik.dylib`
//! ve statik `libkaotik.a`. Başlık dosyası: `include/kaotik.h`.
//!
//! Bellek kuralı: çıktı tamponlarını **kütüphane ayırır** (`KaotikBuf`), çağıran taraf işi bitince
//! `kaotik_buf_free` ile serbest bırakır (içerik önce sıfırlanır). Böylece tampon taşması olamaz.
//!
//! Dönüş kodları: `KAOTIK_OK` (0), `KAOTIK_ERR_ARG` (1), `KAOTIK_ERR_CRYPTO` (2), `KAOTIK_ERR_PANIC` (3).
//! Doğrulama fonksiyonları (`kaotik_verify*`) 1 = geçerli, 0 = geçersiz döndürür.
#![cfg(feature = "ffi")]
// Safety (tüm `unsafe extern "C"` fonksiyonlar için): işaretçiler NULL olabilir (len=0 ise) ya da
// `len` bayt okunabilir belleği göstermelidir; `KaotikBuf*` çıktılar yazılabilir olmalıdır.
#![allow(clippy::missing_safety_doc)]

use crate::hybrid::{self, HybridKemPublicKey, HybridKemSecretKey, HybridSigningKey, HybridVerifyingKey};
use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{ptr, slice};

pub const KAOTIK_OK: i32 = 0;
pub const KAOTIK_ERR_ARG: i32 = 1;
pub const KAOTIK_ERR_CRYPTO: i32 = 2;
pub const KAOTIK_ERR_PANIC: i32 = 3;

/// Kütüphanenin ayırdığı bayt tamponu.
#[repr(C)]
pub struct KaotikBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

unsafe fn input<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if p.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(p, len))
}

unsafe fn input_str<'a>(p: *const u8, len: usize) -> Option<&'a str> {
    std::str::from_utf8(input(p, len)?).ok()
}

unsafe fn emit(out: *mut KaotikBuf, data: Vec<u8>) {
    let boxed = data.into_boxed_slice();
    let len = boxed.len();
    (*out).ptr = Box::into_raw(boxed) as *mut u8;
    (*out).len = len;
}

fn guard<F: FnOnce() -> i32>(f: F) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(KAOTIK_ERR_PANIC)
}

macro_rules! arg {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return KAOTIK_ERR_ARG,
        }
    };
}

macro_rules! crypto {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(_) => return KAOTIK_ERR_CRYPTO,
        }
    };
}

unsafe fn reset(out: *mut KaotikBuf) -> bool {
    if out.is_null() {
        return false;
    }
    (*out).ptr = ptr::null_mut();
    (*out).len = 0;
    true
}

/// `KaotikBuf` içeriğini sıfırlar ve serbest bırakır. NULL veya boş tampon güvenlidir.
#[no_mangle]
pub unsafe extern "C" fn kaotik_buf_free(buf: *mut KaotikBuf) {
    if buf.is_null() || (*buf).ptr.is_null() {
        return;
    }
    let mut b = Box::from_raw(ptr::slice_from_raw_parts_mut((*buf).ptr, (*buf).len));
    crate::crypto::secure_zero(&mut b);
    drop(b);
    (*buf).ptr = ptr::null_mut();
    (*buf).len = 0;
}

// --- Simetrik ------------------------------------------------------------------

/// 32 baytlık rastgele anahtar üretir.
#[no_mangle]
pub unsafe extern "C" fn kaotik_generate_key(out: *mut KaotikBuf) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let k = crypto!(hybrid::generate_key());
        emit(out, k.to_vec());
        KAOTIK_OK
    })
}

unsafe fn key32(p: *const u8, len: usize) -> Option<[u8; 32]> {
    input(p, len)?.try_into().ok().filter(|_| len == 32)
}

/// XChaCha20-Poly1305 ile şifreler (anahtar tam 32 bayt).
#[no_mangle]
pub unsafe extern "C" fn kaotik_seal(
    key: *const u8, key_len: usize,
    msg: *const u8, msg_len: usize,
    aad: *const u8, aad_len: usize,
    out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let mut k = arg!(key32(key, key_len));
        let r = hybrid::seal(&k, arg!(input(msg, msg_len)), arg!(input(aad, aad_len)));
        crate::crypto::secure_zero(&mut k);
        emit(out, crypto!(r));
        KAOTIK_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn kaotik_open(
    key: *const u8, key_len: usize,
    sealed: *const u8, sealed_len: usize,
    aad: *const u8, aad_len: usize,
    out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let mut k = arg!(key32(key, key_len));
        let r = hybrid::open(&k, arg!(input(sealed, sealed_len)), arg!(input(aad, aad_len)));
        crate::crypto::secure_zero(&mut k);
        emit(out, crypto!(r).to_vec());
        KAOTIK_OK
    })
}

// --- Parola tabanlı dosya/veri şifreleme (AES-256-GCM + Argon2id) -------------

#[no_mangle]
pub unsafe extern "C" fn kaotik_encrypt_aes(
    plain: *const u8, plain_len: usize,
    password: *const u8, password_len: usize,
    out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let pw = arg!(input_str(password, password_len));
        let mut cipher = Vec::new();
        crypto!(crate::encrypt_aes(Cursor::new(arg!(input(plain, plain_len))), &mut cipher, pw));
        emit(out, cipher);
        KAOTIK_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn kaotik_decrypt_aes(
    cipher: *const u8, cipher_len: usize,
    password: *const u8, password_len: usize,
    out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let pw = arg!(input_str(password, password_len));
        let mut plain = Vec::new();
        if crate::decrypt_aes(Cursor::new(arg!(input(cipher, cipher_len))), &mut plain, pw).is_err() {
            crate::crypto::secure_zero(&mut plain);
            return KAOTIK_ERR_CRYPTO;
        }
        emit(out, plain);
        KAOTIK_OK
    })
}

/// Kaotik formatı mı? 0 = evet, 2 = hayır.
#[no_mangle]
pub unsafe extern "C" fn kaotik_verify_file(data: *const u8, data_len: usize) -> i32 {
    guard(|| {
        let d = arg!(input(data, data_len));
        crypto!(crate::verify_file(Cursor::new(d)));
        KAOTIK_OK
    })
}

// --- Parola hash ----------------------------------------------------------------

/// Argon2id PHC dizesi (NUL sonlandırmasız UTF-8) üretir.
#[no_mangle]
pub unsafe extern "C" fn kaotik_hash_password(
    password: *const u8, password_len: usize,
    out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let pw = arg!(input_str(password, password_len));
        emit(out, crypto!(crate::passhash::hash_password(pw)).into_bytes());
        KAOTIK_OK
    })
}

/// 1 = parola doğru, 0 = yanlış/geçersiz.
#[no_mangle]
pub unsafe extern "C" fn kaotik_verify_password(
    password: *const u8, password_len: usize,
    phc: *const u8, phc_len: usize,
) -> i32 {
    guard(|| {
        let (Some(pw), Some(h)) = (input_str(password, password_len), input_str(phc, phc_len)) else {
            return 0;
        };
        crate::passhash::verify_password(pw, h) as i32
    })
}

// --- Hibrit KEM / açık anahtarla şifreleme --------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kaotik_kem_keypair(secret_out: *mut KaotikBuf, public_out: *mut KaotikBuf) -> i32 {
    guard(|| {
        if !reset(secret_out) || !reset(public_out) {
            return KAOTIK_ERR_ARG;
        }
        let sk = crypto!(HybridKemSecretKey::generate());
        emit(public_out, sk.public_key().to_bytes());
        emit(secret_out, sk.to_bytes().to_vec());
        KAOTIK_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn kaotik_kem_encapsulate(
    public_key: *const u8, public_len: usize,
    ciphertext_out: *mut KaotikBuf,
    shared_out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(ciphertext_out) || !reset(shared_out) {
            return KAOTIK_ERR_ARG;
        }
        let pk = crypto!(HybridKemPublicKey::from_bytes(arg!(input(public_key, public_len))));
        let (ct, ss) = crypto!(pk.encapsulate());
        emit(ciphertext_out, ct);
        emit(shared_out, ss.to_vec());
        KAOTIK_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn kaotik_kem_decapsulate(
    secret_key: *const u8, secret_len: usize,
    ciphertext: *const u8, ciphertext_len: usize,
    shared_out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(shared_out) {
            return KAOTIK_ERR_ARG;
        }
        let sk = crypto!(HybridKemSecretKey::from_bytes(arg!(input(secret_key, secret_len))));
        let ss = crypto!(sk.decapsulate(arg!(input(ciphertext, ciphertext_len))));
        emit(shared_out, ss.to_vec());
        KAOTIK_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn kaotik_seal_to(
    public_key: *const u8, public_len: usize,
    msg: *const u8, msg_len: usize,
    aad: *const u8, aad_len: usize,
    out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let pk = crypto!(HybridKemPublicKey::from_bytes(arg!(input(public_key, public_len))));
        emit(out, crypto!(hybrid::seal_to(&pk, arg!(input(msg, msg_len)), arg!(input(aad, aad_len)))));
        KAOTIK_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn kaotik_open_from(
    secret_key: *const u8, secret_len: usize,
    sealed: *const u8, sealed_len: usize,
    aad: *const u8, aad_len: usize,
    out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(out) {
            return KAOTIK_ERR_ARG;
        }
        let sk = crypto!(HybridKemSecretKey::from_bytes(arg!(input(secret_key, secret_len))));
        let pt = crypto!(hybrid::open_from(&sk, arg!(input(sealed, sealed_len)), arg!(input(aad, aad_len))));
        emit(out, pt.to_vec());
        KAOTIK_OK
    })
}

// --- Hibrit imza ----------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kaotik_sign_keypair(secret_out: *mut KaotikBuf, public_out: *mut KaotikBuf) -> i32 {
    guard(|| {
        if !reset(secret_out) || !reset(public_out) {
            return KAOTIK_ERR_ARG;
        }
        let sk = crypto!(HybridSigningKey::generate());
        emit(public_out, sk.verifying_key().to_bytes());
        emit(secret_out, sk.to_bytes().to_vec());
        KAOTIK_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn kaotik_sign(
    secret_key: *const u8, secret_len: usize,
    msg: *const u8, msg_len: usize,
    ctx: *const u8, ctx_len: usize,
    sig_out: *mut KaotikBuf,
) -> i32 {
    guard(|| {
        if !reset(sig_out) {
            return KAOTIK_ERR_ARG;
        }
        let sk = crypto!(HybridSigningKey::from_bytes(arg!(input(secret_key, secret_len))));
        emit(sig_out, crypto!(sk.sign(arg!(input(msg, msg_len)), arg!(input(ctx, ctx_len)))));
        KAOTIK_OK
    })
}

/// 1 = imza geçerli (Ed25519 **ve** ML-DSA-87), 0 = geçersiz.
#[no_mangle]
pub unsafe extern "C" fn kaotik_verify(
    public_key: *const u8, public_len: usize,
    msg: *const u8, msg_len: usize,
    ctx: *const u8, ctx_len: usize,
    sig: *const u8, sig_len: usize,
) -> i32 {
    guard(|| {
        let (Some(pk), Some(m), Some(c), Some(s)) = (
            input(public_key, public_len),
            input(msg, msg_len),
            input(ctx, ctx_len),
            input(sig, sig_len),
        ) else {
            return 0;
        };
        match HybridVerifyingKey::from_bytes(pk) {
            Ok(vk) => vk.verify(m, c, s) as i32,
            Err(_) => 0,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> KaotikBuf {
        KaotikBuf { ptr: ptr::null_mut(), len: 0 }
    }

    unsafe fn bytes(b: &KaotikBuf) -> Vec<u8> {
        slice::from_raw_parts(b.ptr, b.len).to_vec()
    }

    #[test]
    fn ffi_seal_to_and_sign_roundtrip() {
        unsafe {
            let (mut sk, mut pk, mut ct, mut pt) = (empty(), empty(), empty(), empty());
            assert_eq!(kaotik_kem_keypair(&mut sk, &mut pk), KAOTIK_OK);
            let msg = b"selam";
            assert_eq!(kaotik_seal_to(pk.ptr, pk.len, msg.as_ptr(), msg.len(), ptr::null(), 0, &mut ct), KAOTIK_OK);
            assert_eq!(kaotik_open_from(sk.ptr, sk.len, ct.ptr, ct.len, ptr::null(), 0, &mut pt), KAOTIK_OK);
            assert_eq!(bytes(&pt), msg);
            // Kısa anahtar → argüman hatası, taşma yok
            assert_eq!(kaotik_seal(msg.as_ptr(), 5, msg.as_ptr(), 5, ptr::null(), 0, &mut pt), KAOTIK_ERR_ARG);
            for b in [&mut sk, &mut pk, &mut ct, &mut pt] {
                kaotik_buf_free(b);
            }

            let (mut ssk, mut spk, mut sig) = (empty(), empty(), empty());
            assert_eq!(kaotik_sign_keypair(&mut ssk, &mut spk), KAOTIK_OK);
            assert_eq!(kaotik_sign(ssk.ptr, ssk.len, msg.as_ptr(), msg.len(), ptr::null(), 0, &mut sig), KAOTIK_OK);
            assert_eq!(kaotik_verify(spk.ptr, spk.len, msg.as_ptr(), msg.len(), ptr::null(), 0, sig.ptr, sig.len), 1);
            assert_eq!(kaotik_verify(spk.ptr, spk.len, msg.as_ptr(), 4, ptr::null(), 0, sig.ptr, sig.len), 0);
            for b in [&mut ssk, &mut spk, &mut sig] {
                kaotik_buf_free(b);
            }
        }
    }
}
