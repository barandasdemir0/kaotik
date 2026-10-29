# Sürüm Doğrulama

Her sürüm GitHub Actions'ta (`.github/workflows/release.yml`) tekrarlanabilir şekilde derlenir,
`SHA256SUMS` Sigstore ile anahtarsız imzalanır ve her arşiv için SLSA kaynak kanıtı (provenance) üretilir.

## 1. Özet (hash) kontrolü

Arşivi, `SHA256SUMS` ve `SHA256SUMS.sigstore.json` dosyalarını aynı klasöre indirin:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

## 2. İmza kontrolü (cosign)

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/barandasdemir0/kaotik/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

`Verified OK` görmelisiniz. Bu, `SHA256SUMS` dosyasının bu depodaki release iş akışı tarafından bir `v*` etiketinde üretildiğini kanıtlar.

## 3. Kaynak kanıtı (SLSA attestation)

```sh
gh attestation verify kaotik-v0.1.0-x86_64-unknown-linux-gnu.tar.gz --repo barandasdemir0/kaotik
```

## 4. Kaynaktan yeniden derleyip karşılaştırma (Linux x86_64)

```sh
git clone https://github.com/barandasdemir0/kaotik && cd kaotik
git checkout v0.1.0
rustup toolchain install 1.97.0
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo -C strip=symbols"
export CFLAGS="-ffile-prefix-map=$PWD=/build -ffile-prefix-map=$HOME/.cargo=/cargo"
cargo +1.97.0 build --release --locked --offline --target x86_64-unknown-linux-gnu
sha256sum target/x86_64-unknown-linux-gnu/release/kaotik
tar -xzf kaotik-v0.1.0-x86_64-unknown-linux-gnu.tar.gz -O kaotik-v0.1.0-x86_64-unknown-linux-gnu/kaotik | sha256sum
```

İki hash aynı olmalıdır. Not: aynı derleyici sürümü ve benzer sistem araç zinciri (glibc/gcc/linker) gerekir;
farklı bir dağıtımda küçük farklar çıkarsa önce `rustc -vV` ve `cc --version` çıktısını karşılaştırın.
