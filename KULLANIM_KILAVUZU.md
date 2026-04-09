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

## 8. Gelismis Guvenlik Modlari

### 8.1 Honey Decrypt (Tuzak Cikti)

Yanlis parola durumunda hata yerine sahte ama anlamli gorunen cikti uretilir:

```bash
kaotik decrypt --input belge.kaos --output acik.txt --mode kaotik --password "GucluParola16!" --honey
```

### 8.2 Chaffing and Winnowing

Gercek payload etrafina sahte paketler ekleme:

```bash
kaotik chaff-pack --input payload.bin --output payload.chaff --password "GucluParola16!" --fake-packets 128
```

Gercek payload'u geri cikarma:

```bash
kaotik chaff-unpack --input payload.chaff --output payload_real.bin --password "GucluParola16!"
```

### 8.3 Dead Man's Switch

Varolan sifreli dosyaya zaman kilidi zarfi ekleme:

```bash
kaotik seal-switch --input belge.kaos --output belge.switch --not-after-unix 1760000000 --emergency-key "AcilAnahtar!"
```

Zarfi acma:

```bash
kaotik unseal-switch --input belge.switch --output belge.kaos --emergency-key "AcilAnahtar!"
```

### 8.4 Steganographic Chaos

Sifreli veriyi tasiyici dosya icine LSB tabanli gizleme:

```bash
kaotik stego-embed --carrier video.bin --input belge.kaos --output video_stego.bin --password "GucluParola16!"
```

Gomulu veriyi cikarma:

```bash
kaotik stego-extract --input video_stego.bin --output belge.kaos --password "GucluParola16!"
```

### 8.5 Multi-Dimensional Key

Parolaya ek baglam katmanlari (GPS ve zaman slotu):

```bash
kaotik encrypt --input belge.txt --output belge.kaos --password "GucluParola16!" --gps "41.0082,28.9784" --time-slot "night-03"
```

Ayni baglam decrypt tarafinda da birebir verilmelidir.

### 8.6 Self-Mutating Mode

Her basarili sifrelemeden sonra lokal durum hash'i guncellenir; sonraki islemde anahtar baglami evrimlesir:

```bash
kaotik encrypt --input belge.txt --output belge.kaos --password "GucluParola16!" --mutating
```

Not: mutation state dosyasi calisma dizininde `.kaotik_mutation_state` olarak tutulur.

### 8.7 Plausible Deniability Katmanlari

Decoy ve hidden katmanli kapsayici olusturma:

```bash
kaotik plausible-create --decoy-input normal.txt --hidden-input gizli.txt --output vault.pdn --decoy-password "DecoyParola16!" --hidden-password "AsilParola16!"
```

Kapsayiciyi parola ile acma (hangi parola dogruysa o katman acilir):

```bash
kaotik plausible-open --input vault.pdn --output cikti.txt --password "DecoyParola16!"
```

### 8.8 Entropy Poisoning + Polymorphic + Quantum Canary

Bu uc katmani encrypt/decrypt akisina opsiyonel olarak ekleyebilirsin:

```bash
kaotik encrypt --input belge.txt --output belge.kaos --password "GucluParola16!" --entropy-poison --polymorphic --quantum-canary
```

Decrypt tarafinda ayni bayraklar verilmeli:

```bash
kaotik decrypt --input belge.kaos --output belge_acik.txt --password "GucluParola16!" --entropy-poison --polymorphic --quantum-canary
```

Not:

1. `--polymorphic` dosyada sabit bir acik header izi birakmadan sarma katmani uygular.
2. `--entropy-poison` runtime kosullariyla ek maskeleme katmani uygular.
3. `--quantum-canary` tasima/bozma durumlarina karsi canary dogrulamasi yapar.
