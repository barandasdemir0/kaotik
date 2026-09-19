# Kaotik Whitepaper (Teknik Taslak)

## Özet

Kaotik, dosya şifreleme için tasarlanmış bir Rust tabanlı kripto sistemidir. Sistem, standart ve kanıtlı primitifleri (AES-256-GCM, Argon2id/PBKDF2, HKDF, ML-KEM/Kyber) kaotik dönüşüm katmanı ile birleştirir. Amaç, standart kripto güvenliğini korurken analiz maliyetini artıran ek bir difüzyon/karıştırma katmanı sağlamaktır.

## 1. Tasarım Hedefleri

1. Platform bağımsız çalışma: Windows, Linux, macOS
2. Güvenli varsayılanlar: güçlü parola politikası, modern KDF
3. Post-quantum hazırlık: Kyber tabanlı mod
4. Kaotik katmanın korunması: ana modda çok katmanlı dönüşüm
5. Determinizm: tam sayı tabanlı kaotik çekirdek ile platformlar arası tutarlılık

## 2. Tehdit Modeli

Sistem aşağıdaki saldırı sınıflarına karşı dayanıklılık hedefler:

1. Pasif dinleme ve ciphertext analizi
2. Yanlış parola ile brute-force denemeleri
3. Ciphertext üzerinde aktif bayt bozma
4. Büyük dosya ile kaynak tüketimi (DoS) denemeleri

Sistem aşağıdaki konuda mutlak iddia yapmaz:

1. Teorik "kırılamazlık" garantisi
2. Bağımsız denetim olmadan kurumsal en yüksek güven sertifikasyonu

## 3. Kriptografik Mimarinin Özeti

### 3.1 Kaotik Mod

Akış:

1. Paroladan anahtar türetme (Argon2id veya geri uyum için PBKDF2)
2. 8 katman integer kaotik dönüşüm:
   - XOR akışı
   - Permütasyon
   - S-box substitüsyonu
3. AES-256-GCM ile kimlik doğrulamalı şifreleme

Not: Kaotik katman tek başına güvenlik varsayımı değildir. Asıl bütünlük/doğrulama temeli AEAD katmanıdır.

### 3.2 AES Modu

1. Sadece AES-256-GCM
2. Chunk tabanlı stream işleme
3. Büyük dosyalar için performans odaklı kullanım

### 3.3 Kyber Modu (Hibrit)

1. ML-KEM (Kyber-1024, NIST en yüksek güvenlik seviyesi) + X25519 (klasik ECDH) ile bağımsız iki paylaşılan sır üretilir
2. İki sır HKDF-SHA256 ile birleştirilir (`kaotik-hybrid-kem-v1`); kafes problemi VEYA eliptik eğri ayrık logaritma problemi tek başına kırılsa bile anahtar güvende kalır (IETF hibrit-KEM taslaklarındaki birleştirici ilkesiyle aynı)
3. Dosya içeriği elde edilen AES-256 anahtarıyla AES-256-GCM ile şifrelenir
4. Her iki gizli anahtar (Kyber + X25519) da tek dosyada parola ile korunur

### 3.4 Calculus Difüzyon Katmanı (Kaotik Mod)

8 katmanlı kaotik zincirin üzerine, ayrık türev/integral (finite difference) tabanlı ek bir
difüzyon katmanı eklenmiştir: `Δf[i] = f[i] - f[i-1]` (ileri fark = ayrık türev), anahtar
akışıyla birlikte uygulanır ve kümülatif toplamla (ayrık integral) tersinir şekilde geri alınır.
Bu katman kaotik zincirin **yerine geçmez**, üstüne eklenir; asıl bütünlük/doğrulama temeli
yine AEAD (AES-256-GCM) katmanıdır.

## 4. KDF Politikası

1. Yeni dosyalar: Argon2id (m_cost=131072 / 128 MiB, t_cost=4, p_cost=1 — OWASP yüksek güvenlik seviyesi)
2. Eski dosyalar: PBKDF2-SHA512 (500000 iterasyon)
3. Geri uyumluluk dosya formatındaki KDF alanı ile sağlanır

## 5. Tam Sayı Tabanlı Kaotik Çekirdek

Sistemde f64 yerine tam sayı aritmetiği kullanılır.

Kazanımlar:

1. Platformlar arası sayısal davranışın öngörülebilir olması
2. IEEE-754 yuvarlama farklılıklarından kaçınma
3. Determinism testlerinin daha stabil yürütülmesi

Bu geçiş güvenliği tek başına "kusursuz" yapmaz; ancak operasyonel tutarlılık ve testlenebilirlik açısından kritik iyileştirmedir.

## 6. Format ve Bütünlük

1. Magic header ile format doğrulama
2. Mod bilgisi ve sürüm alanı
3. AES-GCM auth tag ile aktif bozma tespiti
4. Boyut sınırları ile bellek tüketim saldırılarına karşı koruma

## 7. Test ve Doğrulama Stratejisi

Uygulanan temel test sınıfları:

1. Roundtrip testleri (encrypt -> decrypt)
2. Yanlış parola başarısızlık testleri
3. Tamper testleri (ciphertext byte bozma)
4. Determinism testleri (sabit salt ile aynı katman sonucu)
5. Salt/nonce tazelik testleri

## 8. Sınırlamalar ve Gelecek Çalışmalar

1. Bağımsız üçüncü taraf güvenlik denetimi henüz tamamlanmamıştır.
2. Geniş kapsamlı benchmark raporları geliştirme aşamasındadır.
3. Tauri arayüzü iskelet olarak eklidir; ürün seviyesi UX sertleştirmesi planlanmaktadır.

## 9. Sonuç

Kaotik, standart kriptografik temelleri koruyup kaotik katmanla ek karmaşıklık sağlayan hibrit bir yaklaşım sunar. Tam sayı tabanlı kaotik çekirdek ve genişletilmiş test seti ile sistem, hem mühendislik güvenilirliği hem de platform tutarlılığı açısından güçlü bir seviyeye taşınmıştır.
