# 10/10 Yol Haritası — Detaylı Tarama ve Eksikler

Bu belge tam tarama sonucu ve her kategoride **10/10** için gereken adımları listeler.

---

## Tarama Özeti

### Bulunan ve Giderilen
- **decrypt_kaotik:** Ciphertext boyutu sınırsız okunabiliyordu → `MAX_KAOTIK_SIZE + 32` üst sınırı eklendi (DoS önlemi).

### Kritik Açık Yok
- Hassas veri hata mesajlarında yok; `secure_zero` kullanımı tutarlı; chunk/KEM boyut sınırları var.

### Dikkat Edilmesi Gerekenler
- **unwrap/expect:** Sadece testlerde; lib içinde yok.
- **unsafe:** Sadece `secure_zero` içinde `write_volatile` (standart ve güvenli kullanım).
- **read_to_end:** Kaotik/Kyber modda tüm dosya bellekte; büyük dosya için AES modu dokümante.

---

## Kategori Bazlı 10/10 Hedefleri

### 1. Konsept / Fikir — 8–9/10 → 10/10

| Eksik | Öneri | Zorluk |
|-------|--------|--------|
| Akademik referans | Kaotik haritalar (Lorenz, Rössler, vb.) için kısa referans/bibliyografi (README veya yorum). | Düşük |
| Parametre dokümantasyonu | `derive_extended_params` çıktılarının hangi haritaya gittiğini tek satırlık tablo ile yazmak. | Düşük |
| “Neden 8 katman?” | README’de tek cümle: denge (güvenlik vs. hız) veya referans. | Düşük |

**10/10 için:** Yukarıdaki dokümantasyon + (isteğe bağlı) kısa “Design” bölümü (kaotik katman → AES → format akışı).

---

### 2. Güvenlik — 5–8/10 → 10/10

| Eksik | Öneri | Zorluk |
|-------|--------|--------|
| Bağımsız denetim | Profesyonel güvenlik denetimi (dış kaynak). | Dış kaynak |
| Sabit-zaman | Tüm hassas karşılaştırmalar ve dallanmalar sabit-zamanlı yapılabilir (uzman incelemesi). | Orta |
| Argon2 parametreleri | Bellek/iterasyon sabit ve dokümante (örn. OWASP önerisi). | Düşük |
| Hata mesajı sızıntısı | `Display`/log’da parola, anahtar, salt asla yok (kontrol edildi ✓). | — |
| Kyber key gen | NIST SP 800-203’e uyum notu veya test. | Düşük |

**10/10 için:** Denetim + Argon2 parametre dokümantasyonu + (isteğe bağlı) constant-time incelemesi.

---

### 3. Taşınabilirlik — 3–8/10 → 10/10

| Eksik | Öneri | Zorluk |
|-------|--------|--------|
| f64 determinizm | Kaotik modda f64 kullanımı; aynı Rust derlemesi pratikte tutarlı. Tam garanti için **fixed-point (tamsayı) kaotik** refactor. | Yüksek |
| Cross-compile | `README` veya CI: `cargo build --release --target x86_64-unknown-linux-gnu` vb. örnekleri. | Düşük |
| no_std (isteğe bağlı) | Gömülü için no_std/alloc-only hedefi; büyük iş. | Yüksek |
| Versiyon / format şeması | Format sürümleri ve alanlar için tek sayfa şema (ASCII veya tablo). | Düşük |

**10/10 için:** Cross-compile dokümantasyonu + format şeması + (tam taşınabilirlik istiyorsan) fixed-point kaotik veya “AES/Kyber tek taşınabilir mod” notu.

---

### 4. Kod Kalitesi — 6–8/10 → 10/10

| Eksik | Öneri | Zorluk |
|-------|--------|--------|
| Doc comments | Tüm `pub` fonksiyon ve önemli sabitler için `///` dokümantasyonu. | Orta |
| Clippy | `clippy::all` (ve seçili pedantic) ile temiz çıktı; CI’da `cargo clippy`. | Düşük |
| Test kapsamı | Boş dosya, 1-byte, hatalı format, yanlış parola, chunk sınırı testleri. | Orta |
| Error türü | `#[non_exhaustive]` veya error variant’larının stabil sözleşmesi. | Düşük |
| Modül özeti | Her `*.rs` dosyasının başında 1–2 cümlelik modül açıklaması. | Düşük |

**10/10 için:** Doc comments + Clippy temiz + birkaç ek edge-case testi + modül özetleri.

---

### 5. Ürün Olgunluğu — 4–7/10 → 10/10

| Eksik | Öneri | Zorluk |
|-------|--------|--------|
| GUI | C#/Tk/egui ile basit “dosya seç → mod → şifrele/çöz” arayüzü (ayrı repo veya alt dizin). | Orta–Yüksek |
| Versiyonlama | `Cargo.toml` version + CHANGELOG.md (SemVer). | Düşük |
| Kurulum | Windows: zip/installer; Linux: .deb/AppImage veya cargo install; macOS: brew veya dmg. | Orta |
| Konfigürasyon | (İsteğe bağlı) config dosyası: varsayılan mod, parola kuralları, vb. | Orta |
| Otomasyon | CI (GitHub Actions vb.): build + test + clippy; release artefact. | Düşük |

**10/10 için:** CHANGELOG + SemVer + CI + (isteğe bağlı) GUI veya “GUI ayrı faz” notu + kurulum talimatları.

---

## Öncelik Sırası (Hızlı Kazanımlar Önce)

1. **Hemen:** CHANGELOG.md, `Cargo.toml` version netleştirme, CI (build + test + clippy).
2. **Kısa:** Doc comments (lib + format + crypto), Clippy düzeltmeleri, 2–3 ek test (boş dosya, yanlış parola).
3. **Orta:** Argon2 parametre dokümantasyonu, format şeması, cross-compile notu, modül özetleri.
4. **Uzun:** Güvenlik denetimi, fixed-point kaotik (taşınabilirlik), GUI, paketleme/kurulum.

---

## Güvenlik Kontrol Listesi (Tekrar)

- [x] Parola/anahtar hata mesajında yok
- [x] Hassas buffer’lar `secure_zero`
- [x] Chunk / KEM / kaotik ciphertext boyut sınırı
- [x] Zayıf parola listesi
- [x] Argon2id (yeni), PBKDF2 (eski) geri uyumlu
- [ ] Sabit-zaman tam inceleme (opsiyonel)
- [ ] Bağımsız güvenlik denetimi (dış kaynak)

---

## Özet Tablo (Hedef 10/10)

| Kategori        | 10/10 için ana gereksinimler |
|-----------------|------------------------------|
| **Konsept**     | Kısa referans + parametre/akış dokümantasyonu |
| **Güvenlik**    | Denetim + Argon2 dok + (ops.) constant-time |
| **Taşınabilirlik** | Format şeması + cross-compile + (ops.) fixed-point |
| **Kod Kalitesi**  | Doc comments + Clippy + ek testler + modül özeti |
| **Ürün Olgunluğu** | CHANGELOG + SemVer + CI + (ops.) GUI + kurulum |

Bu adımlar tamamlandıkça her kategori 10/10’a yaklaşır; en büyük etki CI, dokümantasyon ve (ürün için) GUI/kurulum olacaktır.
