# Değişiklik Günlüğü

## v0.2.0 — 2026-10-29

Kaotik artık her uygulamaya gömülebilen, kuantum sonrası **hibrit** bir kripto kütüphanesi.

### Yeni
- **hybrid** — X25519 + ML-KEM-1024 anahtar anlaşması (X-Wing tarzı), Ed25519 + ML-DSA-87 çift imza,
  XChaCha20-Poly1305 `seal/open`, alıcının açık anahtarına `seal_to/open_from`.
- **ratchet** — Kuantum sonrası Double Ratchet: imzalı ön anahtar, karşılıklı kimlik doğrulama,
  başlık şifreleme, sırasız teslim, replay reddi, şifreli durum saklama.
- **group** — Grup sohbeti (Sender Keys), her mesaj hibrit imzalı.
- **hashsig** — SLH-DSA-SHAKE-256s (FIPS 205), kök kimlik anahtarları için.
- **stream** — Sınırsız boyutlu dosya/akış şifreleme (STREAM yapısı).
- **keystore** — Argon2id anahtar kutusu, OS anahtar zinciri (`--features keyring`).
- **passhash** — Argon2id PHC parola hash / doğrulama.
- **Bağlamalar** — C ABI (`include/kaotik.h`), Python (`bindings/python`), WebAssembly (`bindings/js`).
- **Masaüstü** — Tauri uygulamasında `pq` modu.

### Düzeltmeler
- FFI'deki tampon taşması kapatıldı (çıktı tamponlarını artık kütüphane ayırıyor).
- Bozuk çevrimdışı (vendor) derleme onarıldı; `vendor_hashes.txt` taşınabilir biçimde.
- `ctutils` 0.4.7'ye yükseltildi (RUSTSEC-2026-0385: sabit zamanlı olmayan maske/karşılaştırma).
- Not: eski Kyber-768 dosya modunun kullandığı `pqcrypto-*` paketlerinin bakımı bırakıldı (PQClean arşivleniyor); yeni API RustCrypto `ml-kem` kullanır.

### Kalite
- Fuzz hedefleri, dudect zamanlama kontrolü (`examples/ct_check.rs`).
- CI: Linux/Windows/macOS testleri, wasm, Tauri, `cargo audit`, vendor bütünlüğü, fuzz.

### Uyumluluk
- Eski dosya modları (`kaotik`, `aes`, `kyber`) ve dosya biçimleri değişmedi.
- Bağımsız güvenlik denetimi henüz yapılmadı; bkz. `GUVENLIK_MODELI.md`.
