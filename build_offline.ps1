# Offline build script — internet gerektirmez.
# Ön koşul: cargo vendor vendor/ çalıştırılmış ve .cargo/config.toml mevcut olmalı.

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

# İsteğe bağlı: script ile sınırlı Cargo/Rustup home (taşınabilir)
# $env:CARGO_HOME = "$ProjectRoot\.cargo_home"
# $env:RUSTUP_HOME = "$ProjectRoot\.rustup_home"

Write-Host "Building kaotik (offline)..." -ForegroundColor Cyan
cargo build --release --offline
if ($LASTEXITCODE -ne 0) {
    Write-Host "HATA: Derleme basarisiz" -ForegroundColor Red
    exit 1
}

Write-Host "OK: target/release/kaotik.exe (Windows) veya target/release/kaotik (Linux)" -ForegroundColor Green
Write-Host "Running tests (offline)..." -ForegroundColor Cyan
cargo test --release --offline
if ($LASTEXITCODE -ne 0) {
    Write-Host "UYARI: Testler basarisiz" -ForegroundColor Yellow
    exit 1
}
Write-Host "Bitti." -ForegroundColor Green
