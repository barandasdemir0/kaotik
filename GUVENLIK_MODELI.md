# Kaotik Güvenlik Modeli ve Yol Haritası (uzun vadeli koruma)

## Dürüst çerçeve

Hiçbir sistem “100 yıl kesin kırılmaz” garantisi veremez — bunu vaat eden herkes yanılıyordur.
Ulaşılabilecek en iyi hedef şudur:

1. **Matematik:** Bilinen her saldırıya (kuantum dahil) karşı büyük güvenlik payı olan, kamuya açık
   ve on yıllardır analiz edilen algoritmalar kullanmak.
2. **Hibritlik:** Birbirinden bağımsız iki zor probleme aynı anda dayanmak; biri kırılırsa diğeri korur.
3. **Çevikleştirme (crypto-agility):** Her çıktıda sürüm/suite etiketi; yarın bir algoritma zayıflarsa
   veriyi yeni suite ile yeniden sarmak mümkün olsun.
4. **Gerçekçi tehdit:** Pratikte saldırılar matematiği değil cihazı, parolayı, anahtar saklamayı ve
   insanı hedef alır. Uzun ömürlü güvenlik çoğunlukla burada kazanılır/kaybedilir.

> Yapay zekâ ile “tersine mühendislik” konusu: Modern kripto **gizliliğe değil anahtara** dayanır
> (Kerckhoffs ilkesi). Kaynak kodu herkes görebilir; anahtar yoksa çözülemez. Bu yüzden kodu
> gizlemek koruma sağlamaz; anahtarı ve cihazı korumak sağlar.

## Şu an kütüphanede olanlar (`src/hybrid.rs`, `src/passhash.rs`, `src/ffi.rs`)

| Katman | Algoritma | Kuantum sonrası durum |
|--------|-----------|-----------------------|
| Simetrik | XChaCha20-Poly1305, 256-bit anahtar | Grover sonrası ~128 bit — güvenli |
| Anahtar anlaşması | X25519 **+** ML-KEM-1024 (FIPS 203, kategori 5), X-Wing tarzı HKDF-SHA512 birleştirici | Hibrit |
| İmza | Ed25519 (strict) **+** ML-DSA-87 (FIPS 204, kategori 5, hedged); ikisi birden doğrulanmalı | Hibrit |
| Açık anahtarla şifreleme | `seal_to` / `open_from` (KEM ciphertext AAD'ye bağlı) | Hibrit |
| Giriş parolaları | Argon2id PHC hash (64 MiB, t=3), `needs_rehash` | Parola gücüne bağlı |
| Dosya (eski) | Kaotik / AES-GCM / Kyber-768 modları | Geri uyumluluk için duruyor |

Her yerde aynı API: Rust (`kaotik::hybrid`, `kaotik::passhash`) ve C ABI (`include/kaotik.h`,
`--features ffi`) → C/C++, C#, Python (ctypes/cffi), Go (cgo), Swift, Kotlin/Java (JNI), Node (ffi-napi).

## Uygulama türüne göre kullanım

- **Sohbet uygulaması:** Her kullanıcı bir KEM + imza anahtar çifti üretir; açık anahtarlar sunucuda
  yayınlanır. Oturum açılışında `kem_encapsulate` ile ortak sır → `derive_subkey` ile yön bazlı anahtarlar
  → her mesaj `seal(key, msg, aad = sohbet_id||gönderen||sıra_no)`. Kimlik doğrulama için `sign/verify`.
  *İleri gizlilik için Double Ratchet henüz yok (bkz. Adım 6).*
- **Giriş parolaları:** Sunucuda yalnızca `hash_password` çıktısı; `verify_password` ile kontrol.
- **Parola kasası / gizli notlar:** Ana parola → Argon2id → kasa anahtarı; kayıtlar `seal` ile.
- **Dosya:** `seal_to` (alıcı açık anahtarıyla) veya mevcut CLI modları.

## Adım adım yol haritası

- [x] 1. FFI bellek taşması kapatıldı; tamponlar kütüphane tarafından ayrılıyor, panic yakalanıyor.
- [x] 2. Ham anahtarla `seal/open` (parola kuralı ve yapay bekleme yok).
- [x] 3. Parola hash/doğrulama (Argon2id PHC).
- [x] 4. Hibrit KEM (X25519 + ML-KEM-1024) ve hibrit imza (Ed25519 + ML-DSA-87).
- [x] 5. Çevrimdışı vendor derlemesi onarıldı (`vendor/** -text`), `target/` git'ten çıkarıldı.
- [ ] 6. Sohbet için PQ Double Ratchet (ileri gizlilik + ele geçirme sonrası iyileşme), oturum durumu şifreli saklama.
- [ ] 7. Hash tabanlı yedek imza: SLH-DSA (FIPS 205) — yalnızca hash fonksiyonlarına dayanır, en muhafazakâr seçenek.
- [ ] 8. Bağlamalar: wasm-bindgen (web), UniFFI (Kotlin/Swift/Python), Tauri arayüzünü yeni API'ye taşıma.
- [ ] 9. Akış (streaming) `seal` — çok büyük dosyalar için parçalı XChaCha (STREAM yapısı).
- [ ] 10. Anahtar saklama: işletim sistemi anahtar zinciri / Secure Enclave / TPM / donanım anahtarı entegrasyonu.
- [ ] 11. Fuzzing (cargo-fuzz), sabit-zaman testleri (dudect), test vektörleri, `cargo audit` CI.
- [ ] 12. Bağımsız profesyonel güvenlik denetimi — “güvenli” iddiası için tek gerçek kanıt.

Not: Kaotik (kaotik harita) katmanı kendine özgü ve denetlenmemiş bir yapıdır; güvenlik onun üzerine
değil, altındaki standart algoritmalara dayanmalıdır. Yeni uygulamalarda `hybrid` API'si önerilir.
