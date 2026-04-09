$ErrorActionPreference = "Stop"

# 1. Rust kontrolü
try {
    cargo --version | Out-Null
    Write-Host "Rust yuklu, isleme baslaniyor..." -ForegroundColor Green
} catch {
    Write-Error "Rust yuklu degil veya PATH'te bulunamadi. Lutfen Rust'i kurun ve terminali yeniden baslatin."
    exit 1
}

$ConfigPath = ".cargo\config.toml"
$Content = Get-Content $ConfigPath -Raw

# 2. Offline modu geçici kapat
if ($Content -match "offline = true") {
    $Content = $Content -replace "offline = true", "offline = false"
    Set-Content -Path $ConfigPath -Value $Content
    Write-Host "Internet erisimi gecici olarak acildi (offline = false)." -ForegroundColor Cyan
}

# 3. Vendor işlemini başlat
try {
    Write-Host "Bagimliliklar indiriliyor (cargo vendor)... Lutfen bekleyin." -ForegroundColor Yellow
    cargo vendor vendor/
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Vendor islemi BASARILI." -ForegroundColor Green
    } else {
        throw "Vendor islemi basarisiz oldu."
    }
} finally {
    # 4. Offline modu geri aç (her durumda)
    $Content = Get-Content $ConfigPath -Raw
    if ($Content -match "offline = false") {
        $Content = $Content -replace "offline = false", "offline = true"
        Set-Content -Path $ConfigPath -Value $Content
        Write-Host "Internet erisimi tekrar kapatildi (offline = true)." -ForegroundColor Cyan
    }
}

# 5. Cargo.lock oluşturma denemesi
Write-Host "Kilit dosyasi (Cargo.lock) olusturuluyor..." -ForegroundColor Yellow
try {
    cargo check --offline
    Write-Host "Tamamlandi. Artik internet olmadan derleyebilirsiniz." -ForegroundColor Green
} catch {
    Write-Warning "Cargo.lock olustururken hata, ancak vendor klasoru hazir. Manuel deneyebilirsiniz."
}
