"""Kaotik Python bağlaması (ctypes, ek bağımlılık yok).

Kütüphaneyi derleyin:  cargo build --release --features ffi
Ardından KAOTIK_LIB ortam değişkeniyle .so/.dll/.dylib yolunu verin veya varsayılan
`target/release` konumunu kullanın.

    import kaotik
    key = kaotik.generate_key()
    ct = kaotik.seal(key, b"merhaba", aad=b"chat:1")
    assert kaotik.open(key, ct, aad=b"chat:1") == b"merhaba"
"""
import ctypes
import os
import sys
from pathlib import Path


class _Buf(ctypes.Structure):
    _fields_ = [("ptr", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


def _load():
    if os.environ.get("KAOTIK_LIB"):
        return ctypes.CDLL(os.environ["KAOTIK_LIB"])
    name = {"win32": "kaotik.dll", "darwin": "libkaotik.dylib"}.get(sys.platform, "libkaotik.so")
    root = Path(__file__).resolve().parents[2]
    return ctypes.CDLL(str(root / "target" / "release" / name))


_lib = _load()
_P = ctypes.c_char_p
_N = ctypes.c_size_t
_B = ctypes.POINTER(_Buf)
for _name, _args in {
    "kaotik_generate_key": [_B],
    "kaotik_seal": [_P, _N, _P, _N, _P, _N, _B],
    "kaotik_open": [_P, _N, _P, _N, _P, _N, _B],
    "kaotik_encrypt_aes": [_P, _N, _P, _N, _B],
    "kaotik_decrypt_aes": [_P, _N, _P, _N, _B],
    "kaotik_hash_password": [_P, _N, _B],
    "kaotik_verify_password": [_P, _N, _P, _N],
    "kaotik_kem_keypair": [_B, _B],
    "kaotik_seal_to": [_P, _N, _P, _N, _P, _N, _B],
    "kaotik_open_from": [_P, _N, _P, _N, _P, _N, _B],
    "kaotik_sign_keypair": [_B, _B],
    "kaotik_sign": [_P, _N, _P, _N, _P, _N, _B],
    "kaotik_verify": [_P, _N, _P, _N, _P, _N, _P, _N],
}.items():
    _f = getattr(_lib, _name)
    _f.argtypes = _args
    _f.restype = ctypes.c_int32
_lib.kaotik_buf_free.argtypes = [_B]
_lib.kaotik_buf_free.restype = None


class KaotikError(Exception):
    pass


def _take(buf):
    try:
        return ctypes.string_at(buf.ptr, buf.len) if buf.len else b""
    finally:
        _lib.kaotik_buf_free(ctypes.byref(buf))


def _call(fn, *args, outs=1):
    bufs = [_Buf() for _ in range(outs)]
    rc = fn(*args, *[ctypes.byref(b) for b in bufs])
    if rc != 0:
        for b in bufs:
            _lib.kaotik_buf_free(ctypes.byref(b))
        raise KaotikError({1: "invalid argument", 2: "crypto/authentication failure", 3: "internal error"}.get(rc, rc))
    out = [_take(b) for b in bufs]
    return out[0] if outs == 1 else tuple(out)


def _b(x):
    return x.encode() if isinstance(x, str) else bytes(x)


def generate_key() -> bytes:
    return _call(_lib.kaotik_generate_key)


def seal(key: bytes, msg: bytes, aad: bytes = b"") -> bytes:
    return _call(_lib.kaotik_seal, key, len(key), msg, len(msg), aad, len(aad))


def open(key: bytes, sealed: bytes, aad: bytes = b"") -> bytes:  # noqa: A001
    return _call(_lib.kaotik_open, key, len(key), sealed, len(sealed), aad, len(aad))


def encrypt_with_password(data: bytes, password: str) -> bytes:
    pw = _b(password)
    return _call(_lib.kaotik_encrypt_aes, data, len(data), pw, len(pw))


def decrypt_with_password(data: bytes, password: str) -> bytes:
    pw = _b(password)
    return _call(_lib.kaotik_decrypt_aes, data, len(data), pw, len(pw))


def hash_password(password: str) -> str:
    pw = _b(password)
    return _call(_lib.kaotik_hash_password, pw, len(pw)).decode()


def verify_password(password: str, phc: str) -> bool:
    pw, h = _b(password), _b(phc)
    return _lib.kaotik_verify_password(pw, len(pw), h, len(h)) == 1


def kem_keypair():
    """(secret, public)"""
    return _call(_lib.kaotik_kem_keypair, outs=2)


def seal_to(public_key: bytes, msg: bytes, aad: bytes = b"") -> bytes:
    return _call(_lib.kaotik_seal_to, public_key, len(public_key), msg, len(msg), aad, len(aad))


def open_from(secret_key: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    return _call(_lib.kaotik_open_from, secret_key, len(secret_key), sealed, len(sealed), aad, len(aad))


def sign_keypair():
    """(secret, public)"""
    return _call(_lib.kaotik_sign_keypair, outs=2)


def sign(secret_key: bytes, msg: bytes, ctx: bytes = b"") -> bytes:
    return _call(_lib.kaotik_sign, secret_key, len(secret_key), msg, len(msg), ctx, len(ctx))


def verify(public_key: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
    return _lib.kaotik_verify(public_key, len(public_key), msg, len(msg), ctx, len(ctx), sig, len(sig)) == 1
