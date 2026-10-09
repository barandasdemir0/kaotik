/* Kaotik C ABI — build: cargo build --release --features ffi
 * Link: libkaotik.{so,dylib,a} / kaotik.dll
 *
 * Memory: every output is a KaotikBuf allocated by the library.
 * Always release it with kaotik_buf_free() (contents are zeroed first).
 * Return codes: 0 OK, 1 bad argument, 2 crypto/auth failure, 3 internal panic.
 * kaotik_verify / kaotik_verify_password return 1 = valid, 0 = invalid.
 */
#ifndef KAOTIK_H
#define KAOTIK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KAOTIK_OK         0
#define KAOTIK_ERR_ARG    1
#define KAOTIK_ERR_CRYPTO 2
#define KAOTIK_ERR_PANIC  3

typedef struct { uint8_t *ptr; size_t len; } KaotikBuf;

void    kaotik_buf_free(KaotikBuf *buf);

/* Symmetric: XChaCha20-Poly1305, 32-byte key */
int32_t kaotik_generate_key(KaotikBuf *out);
int32_t kaotik_seal(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    const uint8_t *aad, size_t aad_len, KaotikBuf *out);
int32_t kaotik_open(const uint8_t *key, size_t key_len, const uint8_t *sealed, size_t sealed_len,
                    const uint8_t *aad, size_t aad_len, KaotikBuf *out);

/* Password-based data encryption (Argon2id + AES-256-GCM, Kaotik file format) */
int32_t kaotik_encrypt_aes(const uint8_t *plain, size_t plain_len,
                           const uint8_t *password, size_t password_len, KaotikBuf *out);
int32_t kaotik_decrypt_aes(const uint8_t *cipher, size_t cipher_len,
                           const uint8_t *password, size_t password_len, KaotikBuf *out);
int32_t kaotik_verify_file(const uint8_t *data, size_t data_len);

/* Login password hashing (Argon2id PHC string) */
int32_t kaotik_hash_password(const uint8_t *password, size_t password_len, KaotikBuf *phc_out);
int32_t kaotik_verify_password(const uint8_t *password, size_t password_len,
                               const uint8_t *phc, size_t phc_len);

/* Hybrid KEM: X25519 + ML-KEM-1024 */
int32_t kaotik_kem_keypair(KaotikBuf *secret_out, KaotikBuf *public_out);
int32_t kaotik_kem_encapsulate(const uint8_t *public_key, size_t public_len,
                               KaotikBuf *ciphertext_out, KaotikBuf *shared_out);
int32_t kaotik_kem_decapsulate(const uint8_t *secret_key, size_t secret_len,
                               const uint8_t *ciphertext, size_t ciphertext_len, KaotikBuf *shared_out);
int32_t kaotik_seal_to(const uint8_t *public_key, size_t public_len, const uint8_t *msg, size_t msg_len,
                       const uint8_t *aad, size_t aad_len, KaotikBuf *out);
int32_t kaotik_open_from(const uint8_t *secret_key, size_t secret_len, const uint8_t *sealed, size_t sealed_len,
                         const uint8_t *aad, size_t aad_len, KaotikBuf *out);

/* Hybrid signatures: Ed25519 + ML-DSA-87 (both must verify) */
int32_t kaotik_sign_keypair(KaotikBuf *secret_out, KaotikBuf *public_out);
int32_t kaotik_sign(const uint8_t *secret_key, size_t secret_len, const uint8_t *msg, size_t msg_len,
                    const uint8_t *ctx, size_t ctx_len, KaotikBuf *sig_out);
int32_t kaotik_verify(const uint8_t *public_key, size_t public_len, const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len, const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif
#endif /* KAOTIK_H */
