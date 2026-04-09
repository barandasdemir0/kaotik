# Kaotik — Rust crypto library and CLI

Platform-independent encryption. **Kyber:** NIST FIPS 203 ML-KEM (Kyber-768), kuantum direnci. **Kaotik modu:** 8 katman hibrit kaotik + permütasyon + S-box + AES-256-GCM. **AES modu:** yalnizca AES-256-GCM (NIST standart), yani kaotik katman bu modda bilincli olarak kapali. Paroladan anahtar: **Argon2id** (yeni dosyalar) veya PBKDF2 (eski dosyalar, geri uyumlu). Windows, Linux, macOS.

Kisa ozet: Kaotiklik bu projede vardir ve ana moddur; sadece `--mode aes` secilirse kaotik katman kullanilmaz.

---

## Programın çalışma mantığı

### Ne şifrelenir?

Program **dosya** (veya veri akışı) şifreler. Yani:

- **Dosya şifreleme:** `--input` ile verdiğin **herhangi bir dosyanın içeriği** şifrelenir. Dosya türü fark etmez: metin (.txt), resim (.jpg, .png), video (.mp4), PDF, zip, vs. Program dosyayı **byte byte** okuyup şifreleyip `--output` ile verdiğin yeni dosyaya yazar.
- **Sadece metin** şifrelemek istersen: metni bir `.txt` dosyasına kaydedip o dosyayı şifreleyebilirsin; veya metni komut satırından borulayıp stdin ile verebilirsin (`echo "gizli metin" | kaotik encrypt --input - --output - ...`).

Özet: **Girdi = bir dosya yolu veya stdin.** Program o girdinin **tüm içeriğini** (ne olursa olsun: metin, ikili veri) şifreler; çıktı da bir dosya veya stdout olur.

---

Program **komut satırı (CLI)** çalışır: `kaotik <komut> <seçenekler>`.

| Komut | Ne yapar |
|-------|----------|
| **encrypt** | Bir dosyayı (veya stdin) şifreler; çıktıyı dosyaya (veya stdout) yazar. Mod: `kaotik`, `aes` veya `kyber`. |
| **decrypt** | Şifreli dosyayı açar; aynı parola ve (Kyber’da) anahtar dosyası gerekir. |
| **verify** | Dosyanın Kaotik formatında olup olmadığını kontrol eder (parola gerekmez, içerik çözülmez). |

**Üç mod:**

1. **kaotik** — Parola + 8 katman kaotik (XOR, permütasyon, S-box) + AES-256-GCM. Tek parola yeter; büyük dosyalar için bellekte tutulur (max 256 MiB).
2. **aes** — Sadece parola + AES-256-GCM, 64 KiB bloklarla (streaming). Büyük dosyalar için uygun.
3. **kyber** — NIST Kyber-768 (kuantum direnci). Şifrelerken bir **anahtar dosyası** (örn. `secret.key`) oluşturulur; bu dosya parola ile korunur. Çözerken hem parola hem bu anahtar dosyası gerekir.

Parola: En az 16 karakter, büyük harf + rakam + özel karakter. İstersen `KAOTIK_PASSWORD` ortam değişkeni ile verebilirsin (komut satırında görünmez).

---

## Nasıl çalıştırılır?

### 1. Derleme (bir kez)

Rust kurulu olmalı ([rustup.rs](https://rustup.rs)). Proje klasöründe:

```bash
cd kaotik
cargo build --release
```

- **Windows:** `kaotik\target\release\kaotik.exe`
- **Linux/macOS:** `kaotik/target/release/kaotik`

Bu dosyayı PATH’e ekleyebilir veya tam yolu ile çağırabilirsin.

### 2. Şifreleme

```bash
# Kaotik mod (varsayılan)
kaotik encrypt --input belge.txt --output belge.kaos --password "GüçlüParola16!"

# AES mod (büyük dosyalar)
kaotik encrypt --input video.mp4 --output video.kaos --mode aes --password "GüçlüParola16!"

# Kyber mod (anahtar dosyası oluşur)
kaotik encrypt --input gizli.txt --output gizli.kaos --mode kyber --password "GüçlüParola16!" --key-out benim.key
```

### 3. Çözme

```bash
# Kaotik veya AES
kaotik decrypt --input belge.kaos --output belge_acik.txt --password "GüçlüParola16!" --mode kaotik

# Kyber (anahtar dosyası gerekir)
kaotik decrypt --input gizli.kaos --output gizli_acik.txt --mode kyber --password "GüçlüParola16!" --key-file benim.key
```

### 4. Doğrulama ve yardım

```bash
kaotik verify --input belge.kaos
kaotik --version
kaotik --help
kaotik encrypt --help
```

**Stdin/stdout:** `--input -` ve `--output -` ile borulama yapılabilir (örn. `kaotik encrypt --input - --output - --mode aes --password "..." < dosya.txt > dosya.kaos`).

---

## Son adımlar — hazırlık ve sanal PC'de deneme

### Şu an (kendi bilgisayarında) yapacakların

1. **Proje klasörüne gir:** `cd c:\Users\Baran\Desktop\KaotikSifrelemeGUI\kaotik`
2. **Release derle:** `cargo build --release`  
   → Çıktı: `target\release\kaotik.exe` (Windows)
3. **İsteğe bağlı test:** `cargo test`  
   → Hata yoksa devam et.
4. **Sanal PC’ye taşınacaklar:**  
   - `kaotik.exe` → `target\release\kaotik.exe` dosyasını VM’e kopyala.  
   - İstersen bir test dosyası da hazırla (örn. `test.txt` içine birkaç satır yaz).

### Sanal PC’de (Windows) deneme

1. **kaotik.exe**’yi VM’de bir klasöre koy (örn. `Masaüstü\kaotik` veya `C:\kaotik`).
2. **PowerShell veya CMD** aç; o klasöre geç:  
   `cd Masaüstü\kaotik` (veya `cd C:\kaotik`).
3. **Test dosyası oluştur:**  
   `echo Merhaba bu sifreli olacak > test.txt`
4. **Şifrele:**  
   `.\kaotik.exe encrypt --input test.txt --output test.kaos --password "TestParola16!Ab"`
5. **Doğrula:**  
   `.\kaotik.exe verify --input test.kaos`  
   → "OK: file structure valid." görmelisin.
6. **Çöz:**  
   `.\kaotik.exe decrypt --input test.kaos --output test_acik.txt --password "TestParola16!Ab" --mode kaotik`
7. **Karşılaştır:**  
   `type test_acik.txt`  
   → "Merhaba bu sifreli olacak" (ve boş satır) görünmeli.

Sanal PC’de Rust kurmaya gerek yok; sadece **kaotik.exe** yeterli. Linux VM’de ise orada `cargo build --release` yapıp `target/release/kaotik` kullanırsın (veya Linux için kendi makinede cross-compile edebilirsin).

---

## Build (geliştirici)

Requires Rust (rustup). From the `kaotik` directory:

```bash
cargo build --release
```

Binary: `target/release/kaotik.exe` (Windows) or `target/release/kaotik` (Unix).

**Windows:** Varsayılan olarak MSVC toolchain kullanın (`rustup default stable-x86_64-pc-windows-msvc`). `pqcrypto-kyber` genelde saf Rust/assembly ile derlenir; sorun olursa Visual Studio Build Tools veya `cargo build` hata çıktısına göre ek bağımlılık gerekebilir.

## Offline / Sıfır bağımlılık

Tüm kaynakları projeye alıp internetsiz derlemek için:

1. İlk kez (internet açıkken): `.cargo/config.toml` içinde `offline = true` satırını geçici kapatın, `cargo vendor vendor/` çalıştırın, sonra config’i geri açın.
2. Sonrasında: `.\build_offline.ps1` ile offline derleme.
3. Vendor hash’leri ve tam adımlar: **[OFFLINE_BUILD.md](OFFLINE_BUILD.md)**.

## Usage (özet)

Tüm komut örnekleri yukarıdaki **Nasıl çalıştırılır?** bölümünde. Parola kuralları: en az 16 karakter, bir büyük harf, bir rakam, bir özel karakter; zayıf parola listesinde olmamalı.

**Güvenlik:** Parolayı mümkünse `KAOTIK_PASSWORD` ortam değişkeni ile verin; `--password` işlem listesinde görünebilir. Hassas bellek kullanım sonrası sıfırlanır; Kyber sabit-zamanlı karşılaştırma ve rejection sampling kullanır. Bozuk/zararlı dosyaya karşı: AES chunk boyutu en fazla 16 MiB, Kyber KEM ciphertext uzunluğu sınırlıdır. **Bu yazılım bağımsız bir güvenlik denetiminden geçmemiştir;** yüksek risk senaryolarında dikkatli kullanın. Bağımlılıkları (`cargo update`, güvenlik yamaları) güncel tutun.

### KDF ve nonce/salt politikası

1. Yeni dosyalarda varsayılan KDF `Argon2id` kullanılır: `m_cost=65536` (64 MiB), `t_cost=3`.
2. Eski dosyalar için geri uyumluluk amacıyla `PBKDF2-SHA512` (`500_000` iterasyon) desteklenir.
3. Her yeni şifrelemede rastgele `salt` ve `nonce` üretilir; aynı parola/girdi ile bile metadata tekrar etmez.
4. AES streaming modunda her blok için `nonce_for_chunk` ile benzersiz nonce türetilir.

## Tests

```bash
cargo test
cargo test --release -- --ignored   # kaotik boyut limiti testi (257 MiB)
```

## CI

GitHub Actions: `.github/workflows/ci.yml` — `cargo fmt --check`, `cargo build --release`, `cargo test`, `cargo clippy`.

## C FFI

Python/Go/C gibi dillerden çağrı için:

```bash
cargo build --release --features ffi
```

Oluşan kütüphanede `kaotik_encrypt_aes`, `kaotik_decrypt_aes`, `kaotik_verify_file` export edilir. Header üretmek için `cbindgen` kullanılabilir.

## WASM

`wasm` feature ile (Kyber hariç) `wasm32-unknown-unknown` hedeflenebilir. Bazı bağımlılıklar WASM’de sınırlı olduğu için ayrı bir feature/alt crate ile denemeniz gerekebilir.

## Notlar ve sınırlamalar

| Konu | Açıklama |
|------|----------|
| **f64 (kaotik)** | Kaotik modda `f64` kullanılıyor. Rust IEEE 754’e uygun; aynı derleme (aynı hedef, aynı `--release`) pratikte platformda tutarlı sonuç verir. Başka dilde (Python/JS) aynı kaotik katmanı port ederseniz f64 davranışı farklı olabilir; böyle senaryoda **AES** veya **Kyber** modu tercih edin. |
| **Kaotik + büyük dosya** | Kaotik mod tüm plaintext’i belleğe alır (8 katman XOR + permütasyon + S-box). Çok büyük dosyalar için **AES modu** (streaming) kullanın. |
| **S-box determinizm** | S-box sıralaması artık eşit `f64` değerlerde indeks ile kırılıyor; platformlar arası aynı girdi → aynı S-box. |
| **Zayıf parola listesi** | Yalnızca sınırlı sayıda yaygın parola engelleniyor. Yüksek güvenlik ortamlarında harici liste (örn. rockyou) veya parola gücü (zxcvbn) entegrasyonu düşünülebilir. |
| **cargo test (Windows)** | `pqcrypto-kyber` genelde ek C derleyici gerektirmez. Testler çalışmıyorsa MSVC toolchain ve güncel Rust sürümü kullanın. |
