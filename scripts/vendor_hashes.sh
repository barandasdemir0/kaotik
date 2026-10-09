#!/usr/bin/env bash
# vendor/ altındaki tüm dosyaların SHA-256 listesini üretir veya doğrular.
# Biçim (PowerShell betiğiyle aynı): "<BÜYÜK_HARF_HEX> vendor/yol/dosya", yola göre bayt sıralı, LF, BOM yok.
#   scripts/vendor_hashes.sh          -> vendor_hashes.txt
#   scripts/vendor_hashes.sh --check  -> fark varsa çıkış kodu 1
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d vendor ] || { echo "vendor/ yok. Önce: cargo vendor vendor" >&2; exit 1; }
gen() {
  find vendor -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum \
    | awk '{ h=toupper($1); $1=""; sub(/^ +/, ""); print h " " $0 }'
}
if [ "${1:-}" = "--check" ]; then
  [ -f vendor_hashes.txt ] || { echo "vendor_hashes.txt yok" >&2; exit 1; }
  if diff <(gen) vendor_hashes.txt > vendor_hashes_check.diff; then
    rm -f vendor_hashes_check.diff; echo "OK: vendor/ hash'leri referansla aynı."
  else
    echo "UYARI: vendor/ içeriği değişmiş! Ayrıntı: vendor_hashes_check.diff" >&2; exit 1
  fi
else
  gen > vendor_hashes.txt
  echo "vendor_hashes.txt yazıldı ($(wc -l < vendor_hashes.txt) dosya)."
fi
