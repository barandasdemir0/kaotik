#!/bin/bash -eu
# Kök .cargo/config.toml crates.io'yu vendor/ ile değiştirip offline yapar; vendor/ içinde
# libfuzzer-sys/arbitrary yok. Cargo bu yönlendirmeyi env/--config ile geri alamaz, bu yüzden
# yalnızca bu build konteynerindeki kopyada kaldırılır (repoya dokunulmaz).
cd "$SRC/kaotik"
rm -f .cargo/config.toml

cd fuzz
cargo fuzz build -O
TARGETS="parse decrypt sign_verify chaotic_roundtrip kem"
for t in $TARGETS; do
  cp "target/x86_64-unknown-linux-gnu/release/$t" "$OUT/"
  if [ -d "seeds/$t" ]; then
    (cd "seeds/$t" && zip -q -j "$OUT/${t}_seed_corpus.zip" ./*)
  fi
done
