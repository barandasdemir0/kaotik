# Sıfır Bağımlılık — Offline Derleme

Bu rehber, crates.io veya internet olmadan derleme ve değişiklik algılama için adımları özetler.

## Tehdit modeli

| Senaryo | Çözüm |
|--------|--------|
| crates.io çöktü/kapandı | Tüm kaynak `vendor/` içinde; offline derleme |
| Bir crate hacklendi | Cargo.lock + vendor hash’leri ile sabit sürüm ve bütünlük |
| Crate desteği kesildi | Vendor’daki kod sende; güncelleme zorunlu değil |
| Rust sitesi kapandı | Rust offline installer’ı (USB’de) ile derleyici |

## Adım 1: Vendor (ilk kez, internet gerekir)

**.cargo/config.toml** projede vendored + offline kullanacak şekilde ayarlı. İlk kez vendor almak için:

1. `.cargo/config.toml` içinde `[net] offline = true` satırını geçici olarak `offline = false` yapın veya yoruma alın.
2. Çalıştırın:

```powershell
cd kaotik
cargo vendor vendor/
```

3. `[net] offline = true` satırını geri getirin.
4. `vendor/` klasörünü ve `Cargo.lock` dosyasını (henüz yoksa `cargo build` ile oluşan) projeye ekleyin.

Sonuç: Tüm bağımlılık kaynakları `vendor/` altında; sonrasında derleme tamamen offline yapılabilir.

## Adım 2: Offline derleme ayarı

**.cargo/config.toml** zaten şunu kullanır:

- `crates-io` → `vendored-sources` (kaynak olarak `vendor/`)
- `[net] offline = true`

Bu config ile `cargo build` internete çıkmaz. `vendor/` yoksa önce Adım 1’i uygulayın.

## Adım 3: Sürüm sabitleme

- **Cargo.lock**’u Git’e ekleyin: `git add Cargo.lock`
- Böylece her crate’in tam sürümü ve transitive bağımlılıklar sabitlenir; vendor ile uyumsuzlukta Cargo derlemeyi reddeder.

## Adım 4: Vendor hash’leri (değişiklik algılama)

İlk kez (vendor aldıktan sonra):

```powershell
.\scripts\vendor_hashes.ps1
```

Çıkan **vendor_hashes.txt**’i güvenli yerde (USB, ayrı disk) saklayın.

Periyodik kontrol:

```powershell
.\scripts\vendor_hashes.ps1 -Check
```

Fark varsa script uyarır; çıktı boşsa vendor değişmemiştir.

## Adım 5: Rust derleyicisini arşivle

- `rustc --version` ile sürümü görün (örn. 1.xx.0).
- [static.rust-lang.org/dist/](https://static.rust-lang.org/dist/) üzerinden ilgili offline installer’ı indirip USB/arşive kopyalayın, örn.:
  - Windows: `rust-1.xx.0-x86_64-pc-windows-msvc.msi`
  - Linux: `rust-1.xx.0-x86_64-unknown-linux-gnu.tar.gz`

Böylece Rust sitesi kapansa bile aynı sürümle derleyebilirsiniz.

## Adım 6: Offline build script

Proje kökünde:

```powershell
.\build_offline.ps1
```

Bu script `cargo build --release --offline` ve `cargo test --offline` çalıştırır; internet gerekmez.

## Adım 7: Binary’yi sakla

- Windows: `target\release\kaotik.exe`
- Linux: `target/release/kaotik`

Bu dosyayı USB/arşive kopyalayın. Rust veya vendor olmasa bile, bu binary ile şifreli dosyalarınızı açabilirsiniz.

## Kontrol listesi

- [ ] 1. `cargo vendor vendor/` (ilk kez internet açıkken)
- [ ] 2. `.cargo/config.toml` mevcut (vendored + offline)
- [ ] 3. `Cargo.lock` Git’e eklendi
- [ ] 4. `.\scripts\vendor_hashes.ps1` → vendor_hashes.txt oluşturuldu ve USB’ye kopyalandı
- [ ] 5. Rust offline installer indirilip USB’ye kopyalandı
- [ ] 6. `build_offline.ps1` proje kökünde mevcut
- [ ] 7. `kaotik.exe` / `kaotik` binary’si USB’ye kopyalandı
- [ ] 8. Tüm proje (vendor dahil) USB’ye yedeklendi

## Özet tablo

| Bağımlılık | Offline plan öncesi | Sonrası |
|------------|----------------------|---------|
| crates.io (internet) | Gerekli | Gereksiz (vendor) |
| Rust derleyicisi (online) | rustup ile | Offline installer (USB) |
| İnternet | Build için gerekli | Tamamen offline mümkün |
