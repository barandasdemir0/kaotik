# Vendor klasorundeki tum dosyalarin SHA-256 hash'ini yazar.
# Kullanim: .\scripts\vendor_hashes.ps1  -> vendor_hashes.txt
# Kontrol: .\scripts\vendor_hashes.ps1 -Check  -> vendor_hashes_check.txt ve fark varsa uyari

param(
    [switch]$Check
)

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VendorDir = Join-Path $ProjectRoot "vendor"
$OutFile = if ($Check) { "vendor_hashes_check.txt" } else { "vendor_hashes.txt" }
$OutPath = Join-Path $ProjectRoot $OutFile

if (-not (Test-Path $VendorDir)) {
    Write-Error "vendor/ bulunamadi. Once 'cargo vendor vendor/' calistirin."
    exit 1
}

Set-Location $ProjectRoot
$hashes = Get-ChildItem -Recurse -File $VendorDir | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    "$($hash.Hash) $($_.FullName)"
}
$hashes | Out-File -FilePath $OutPath -Encoding utf8

if ($Check) {
    $refPath = Join-Path $ProjectRoot "vendor_hashes.txt"
    if (-not (Test-Path $refPath)) {
        Write-Warning "vendor_hashes.txt yok. Once hash'leri olusturun: .\scripts\vendor_hashes.ps1"
        exit 0
    }
    $ref = Get-Content $refPath
    $diff = Compare-Object $ref $hashes
    if ($diff) {
        Write-Host "UYARI: vendor/ icerigi degismis!" -ForegroundColor Red
        $diff
        exit 1
    }
    Write-Host "OK: vendor/ hash'leri referansla ayni." -ForegroundColor Green
} else {
    Write-Host "Hash'ler yazildi: $OutPath" -ForegroundColor Green
    Write-Host "Bu dosyayi guvenli yerde (USB vb.) saklayin; ayda bir -Check ile kontrol edin." -ForegroundColor Cyan
}
