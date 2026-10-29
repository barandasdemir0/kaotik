# ct-check

dudect tarzı zamanlama testi: `chaotic2::apply` ve `crypto::ct_eq` için iki girdi sınıfı
(sabit / rastgele gizli veri) ölçülür, Welch t-testinin en büyük |t| değeri yazdırılır.
|t| < 4.5 → tespit edilebilir sızıntı yok.

```sh
cd ct-check
cargo run --release -- 1000000   # örnek sayısı (varsayılan 200000)
```

Harici bağımlılık yok; depo içinde `--offline` ile de derlenir. Sonuç gürültülü bir
makinede oynayabilir; birkaç kez çalıştırın. Not: tek süreçli duvar saati ölçümü,
paylaşımlı önbellek saldırısını (ör. Prime+Probe) tam modellemez.
