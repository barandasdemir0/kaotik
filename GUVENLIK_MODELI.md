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

## Kütüphanede olanlar

| Modül | İşlev | Algoritma | Dayandığı varsayım |
|-------|-------|-----------|--------------------|
| `hybrid` | Simetrik `seal`/`open` | XChaCha20-Poly1305, 256-bit | Grover sonrası ~128 bit |
| `hybrid` | Anahtar anlaşması, `seal_to` | X25519 **+** ML-KEM-1024 (FIPS 203), X-Wing tarzı birleştirici | Eğri **ve** kafes |
| `hybrid` | İmza | Ed25519 **+** ML-DSA-87 (FIPS 204); ikisi de doğrulanmalı | Eğri **ve** kafes |
| `hashsig` | Kök kimlik imzası | SLH-DSA-SHAKE-256s (FIPS 205) | Yalnızca hash (en muhafazakâr) |
| `ratchet` | Sohbet oturumu | KEM tabanlı Double Ratchet + imzalı ön anahtar + karşılıklı kimlik doğrulama | İleri gizlilik + ele geçirme sonrası iyileşme |
| `stream` | Büyük dosya/akış | STREAM (parça + son-parça bayrağı), `seal_stream_to` | Kesme/sıra değiştirme tespiti |
| `keystore` | Anahtar saklama | Argon2id (256 MiB) kutusu; `--features keyring` ile OS anahtar zinciri | Parola gücü / OS güvenliği |
| `passhash` | Giriş parolaları | Argon2id PHC, `needs_rehash` | Parola gücü |
| (eski) | Dosya modları | Kaotik / AES-GCM / Kyber-768 | Geri uyumluluk |

### Bağlamalar

| Platform | Nasıl |
|----------|-------|
| Rust | `kaotik::{hybrid, ratchet, stream, keystore, passhash, hashsig}` |
| C / C++ / Go (cgo) / Swift / Kotlin-Java (JNI) / C# (P/Invoke) | `cargo build --release --features ffi` → `libkaotik.{so,dylib,a}` / `kaotik.dll` + `include/kaotik.h` |
| Python | `bindings/python/kaotik.py` (ctypes, bağımlılık yok) |
| Web / Node / Deno | `cargo build --target wasm32-unknown-unknown --features wasm --lib` + `wasm-bindgen` (bkz. `bindings/js/README.md`) |
| Masaüstü | Tauri uygulamasında yeni `pq` modu (XChaCha20 + Argon2id, sınırsız boyut) |

## Uygulama türüne göre kullanım

- **Sohbet uygulaması:** Her kullanıcı bir KEM + imza anahtar çifti üretir; açık anahtarlar sunucuda
  yayınlanır. Oturum açılışında `kem_encapsulate` ile ortak sır → `derive_subkey` ile yön bazlı anahtarlar
  → her mesaj `seal(key, msg, aad = sohbet_id||gönderen||sıra_no)`. Kimlik doğrulama için `sign/verify`.
  Daha iyisi: `ratchet::Session` — her mesaj ayrı anahtar, her turda yeni KEM anahtarı.
  Oturum durumu `export(cihaz_anahtarı)` ile şifreli saklanır; cihaz anahtarı `keystore::os::device_key`.
  Kullanıcılar birbirinin kimlik anahtarını bir kez yüz yüze/QR ile doğrulamalıdır (MITM'e karşı tek gerçek önlem).
  Not: KEM tabanlı başlık her mesajda ~3,2 KiB ek yük getirir (kuantum güvenliğinin bedeli).
- **Giriş parolaları:** Sunucuda yalnızca `hash_password` çıktısı; `verify_password` ile kontrol.
- **Parola kasası / gizli notlar:** Ana parola → Argon2id → kasa anahtarı; kayıtlar `seal` ile.
- **Dosya:** `seal_to` (alıcı açık anahtarıyla) veya mevcut CLI modları.

## Adım adım yol haritası

- [x] 1. FFI bellek taşması kapatıldı; tamponlar kütüphane tarafından ayrılıyor, panic yakalanıyor.
- [x] 2. Ham anahtarla `seal/open` (parola kuralı ve yapay bekleme yok).
- [x] 3. Parola hash/doğrulama (Argon2id PHC).
- [x] 4. Hibrit KEM (X25519 + ML-KEM-1024) ve hibrit imza (Ed25519 + ML-DSA-87).
- [x] 5. Çevrimdışı vendor derlemesi onarıldı, `target/` git'ten çıkarıldı.
- [x] 6. PQ Double Ratchet (`ratchet`): imzalı ön anahtar, karşılıklı kimlik doğrulama, sırasız teslim, replay reddi, hatada durum geri alma, şifreli dışa aktarma.
- [x] 7. SLH-DSA-SHAKE-256s (`hashsig`) — kök kimlik anahtarları için.
- [x] 8. Bağlamalar: C ABI (ratchet dahil), Python, WebAssembly; Tauri'de `pq` modu.
- [x] 9. Akış şifreleme (`stream`): sabit bellek, kesme/ekleme/sıra saldırılarına dayanıklı.
- [x] 10. Anahtar saklama (`keystore`): Argon2id kutusu + OS anahtar zinciri (Keychain / Credential Manager / keyutils).
- [x] 11. Fuzz hedefleri (`fuzz/`), CI: 3 işletim sistemi test, wasm derleme, `cargo audit`, fuzz duman testi.
- [ ] 12. **Bağımsız profesyonel güvenlik denetimi** — kod yazarak yapılamaz; dış uzman gerekir.

### Hâlâ bilinen sınırlar (dürüstçe)

- `ml-kem`, `ml-dsa`, `slh-dsa` (RustCrypto) henüz bağımsız denetimden geçmedi; `slh-dsa` sürüm adayı (rc).
  Hibrit tasarım bu yüzden var: biri hatalıysa klasik bileşen korur.
- Sabit-zaman davranışı bağımlılıklara emanet; dudect tarzı ölçüm yapılmadı.
- Ratchet başlıkları şifrelenmiyor (meta veri: tur ve mesaj numarası görünür). Sunucu kimin kiminle
  ne zaman konuştuğunu görebilir; bunu gizlemek ayrı bir ağ katmanı (ör. sealed sender, Tor) işidir.
- Grup sohbeti (MLS) yok; birebir oturumlar var.
- Cihaz ele geçirilirse (kötü amaçlı yazılım, kilidi açık telefon) hiçbir şifreleme o anki mesajları koruyamaz.

Not: Kaotik (kaotik harita) katmanı kendine özgü ve denetlenmemiş bir yapıdır; güvenlik onun üzerine
değil, altındaki standart algoritmalara dayanmalıdır. Yeni uygulamalarda `hybrid` API'si önerilir.
