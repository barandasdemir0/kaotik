# chaotic.rs Teknik Dokumantasyon

Bu dokuman, [chaotic.rs](chaotic.rs) dosyasinin amacini, ic akislarini ve sinirlarini aciklar.

## Amac

[chaotic.rs](chaotic.rs), parola ve salt girdisinden deterministik bir kaotik dizi uretip bunu cok katmanli bir bayt donusum zincirinde kullanir.

Uygulanan katmanlar:
1. HKDF tabanli XOR akisi
2. Deterministik permutasyon
3. Kaotik S-box substitusyonu

Bu islem [apply_chaotic_xor_layers](chaotic.rs#L285) ile uygulanir ve [reverse_chaotic_xor_layers](chaotic.rs#L311) ile terslenir.

## Genel Akis

1. Parametre turetimi: [derive_extended_params](chaotic.rs#L22)
2. Hibrit kaotik dizi: [generate_hybrid_sequence](chaotic.rs#L124)
3. Dizi hash zinciri: [layer_hashes](chaotic.rs#L266)
4. Her katmanda:
   - HKDF anahtar akisi ile XOR
   - Permutasyon
   - S-box substitusyonu

Katman sayisi [LAYERS](chaotic.rs#L6) ile sabitlenmistir.

## Kullanilan Kaotik Bilesenler

Hibrit dizi asagidaki sistemleri birlestirir:
1. Logistic map
2. Henon map
3. Lorenz sistemi
4. Rossler sistemi
5. Tent map
6. Cubic map

Bu birlestirme [generate_hybrid_sequence](chaotic.rs#L124) icinde agirlikli ortalama ile normalize edilerek tek bir [0,1) diziye indirgenir.

## Fonksiyon Ozeti

1. [wrap01](chaotic.rs#L14): Degeri [0,1) araligina sarar.
2. [derive_extended_params](chaotic.rs#L22): Parola, salt, katman ve onceki katman hash degerinden 12 adet parametre turetir.
3. [lorenz_step](chaotic.rs#L52), [rossler_step](chaotic.rs#L66): Surekli sistemlerin sayisal adimlarini uygular.
4. [tent_map](chaotic.rs#L80), [cubic_map](chaotic.rs#L91): Ayrik map guncellemesi yapar.
5. [chaotic_sequence_to_prk](chaotic.rs#L98): Kaotik diziyi byte dizisine cevirip parola ve salt ile birlestirerek PRK ham girdisi olusturur.
6. [generate_chaotic_key_hkdf](chaotic.rs#L112): HKDF cikisindan katman uzunlugunda anahtar akisi uretir.
7. [chaos_sbox](chaotic.rs#L188): Deterministik 256 elemanli S-box turetir.
8. [chaos_permutation](chaotic.rs#L228): Diziye bagli Fisher-Yates benzeri permutasyon olusturur.
9. [apply_chaotic_xor_layers](chaotic.rs#L285): Sifreleme yonu katman uygulamasi.
10. [reverse_chaotic_xor_layers](chaotic.rs#L311): Cozme yonu ters katman uygulamasi.

## Determinizm ve Uyumluluk

Bu dosya tasarimi geregi deterministiktir: ayni parola, ayni salt ve ayni veri boyu icin ayni donusum uretilir.

Sayisal hesaplarda [f64] kullanildigindan, platformlar arasi tam bit-duzey esdegerlikte asagidaki noktalar izlenmelidir:
1. Derleyici surumu sabitlenmeli
2. Hedef platform karmasi test edilmeli
3. Girdi formati ve katman sirasi degistirilmemeli

## Guvenlik Notlari

Bu dosya bir donusum katmani saglar. Tek basina tum guvenlik gereksinimlerini kapsadigi varsayilmamalidir.

Ozellikle:
1. Butunluk/dogrulama (auth tag) ayri olarak garanti edilmelidir.
2. Salt tekrar kullanimi engellenmelidir.
3. Parola gucu kritik oldugu icin dis katmanda guclu parola turetme politikasi uygulanmalidir.

## Performans Notlari

Maliyet, veri boyu ve katman sayisi ile lineer artar; her katmanda birden cok kaotik iterasyon calistirildigi icin buyuk dosyalarda gecikme beklenir.

Ayarlanabilir sabitler:
1. [LAYERS](chaotic.rs#L6)
2. [LORENZ_ITER](chaotic.rs#L8)
3. [ROSSLER_ITER](chaotic.rs#L10)

## Bakim ve Gelistirme Onerisi

1. Fonksiyonel esitlik testleri: `apply` ardindan `reverse` tum veri setlerinde bire bir donmeli.
2. Cok platformlu regresyon testleri: Windows/Linux farkli hedeflerde ayni girdiye ayni cikti.
3. Determinizm testleri: katman hash zinciri surumler arasi korunmali.
4. Performans benchmarklari: buyuk veri boyutlarinda katman maliyeti olculmeli.

## Kapsam

Bu dokuman sadece [chaotic.rs](chaotic.rs) icin hazirlanmistir ve diger modullerin (format, FFI, UI, paketleme) davranisini kapsamaz.