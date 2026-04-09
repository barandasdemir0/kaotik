# Kaotik Kullanım Kılavuzu

Bu kılavuz, Kaotik aracını günlük kullanım için adım adım anlatır.

## 1. Hızlı Başlangıç

1. Proje dizinine girin:

```bash
cd kaotik
```

2. Release derleme yapın:

```bash
cargo build --release
```

3. Çalıştırılabilir dosya:

- Windows: `target/release/kaotik.exe`
- Linux/macOS: `target/release/kaotik`

## 2. Temel Komutlar

### 2.1 Şifreleme

Kaotik mod (varsayılan):

```bash
kaotik encrypt --input belge.txt --output belge.kaos --password "GucluParola16!"
```

AES modu:

```bash
kaotik encrypt --input video.mp4 --output video.kaos --mode aes --password "GucluParola16!"
```

Kyber modu:

```bash
kaotik encrypt --input gizli.txt --output gizli.kaos --mode kyber --password "GucluParola16!" --key-out benim.key
```

### 2.2 Çözme

Kaotik veya AES:

```bash
kaotik decrypt --input belge.kaos --output belge_acik.txt --password "GucluParola16!" --mode kaotik
```

Kyber:

```bash
kaotik decrypt --input gizli.kaos --output gizli_acik.txt --mode kyber --password "GucluParola16!" --key-file benim.key
```

### 2.3 Doğrulama

```bash
kaotik verify --input belge.kaos
```

## 3. Mod Seçimi

1. `kaotik`: Ana mod. Çok katmanlı kaotik dönüşüm + AES-256-GCM.
2. `aes`: Büyük dosya ve hız önceliği için stream tabanlı AES-256-GCM.
3. `kyber`: Post-quantum anahtar kapsülleme + AES katmanı.

## 4. Parola Politikası

Parola şu koşulları sağlamalıdır:

1. En az 16 karakter
2. En az bir büyük harf
3. En az bir rakam
4. En az bir özel karakter

Parolayı komut satırında görünür vermek yerine ortam değişkeni kullanın:

```bash
# Windows PowerShell
$env:KAOTIK_PASSWORD="GucluParola16!"
kaotik encrypt --input belge.txt --output belge.kaos
```

## 5. Güvenlik Pratikleri

1. Aynı dosyada her zaman yeni şifreleme çalıştırın; metadata (salt/nonce) otomatik yenilenir.
2. `kyber` modunda `.key` dosyasını ayrı ve güvenli bir yerde saklayın.
3. Kritik ortamda düzenli `cargo update` ve güvenlik güncellemeleri uygulayın.
4. Dağıtımdan önce `cargo test --release` çalıştırın.

## 6. Sorun Giderme

### Hata: Missing --password or KAOTIK_PASSWORD

Çözüm:

1. `--password` verin veya
2. `KAOTIK_PASSWORD` ortam değişkeni atayın.

### Hata: Not a ... format file

Çözüm:

1. Doğru modu seçtiğinizi kontrol edin.
2. Dosya başlığını `verify` ile doğrulayın.

### Hata: Kyber requires --key-file / --key-out

Çözüm:

1. `encrypt --mode kyber` için `--key-out`
2. `decrypt --mode kyber` için `--key-file`

## 7. Dağıtım Öncesi Kontrol

```bash
cargo fmt --all -- --check
cargo clippy --release -- -D warnings
cargo test --release
```

Bu üç kontrol yeşil ise temel kalite kapısı geçilmiş olur.
