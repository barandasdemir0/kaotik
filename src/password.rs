//! Parola kuralları: uzunluk, büyük harf/rakam/özel karakter, zayıf parola listesi.
use crate::error::{Error, Result};
use subtle::ConstantTimeEq;

const MIN_LENGTH: usize = 16;
/// Yaygın zayıf parolalar (küçük harf eşleştirmesi).
static WEAK_PASSWORDS: &[&str] = &[
    "password123",
    "password123!",
    "Password123!",
    "admin123",
    "admin123!",
    "12345678",
    "1234567890123456",
    "qwerty123",
    "welcome123",
    "letmein123",
    "changeme123",
    "Summer2024!",
    "Winter2024!",
];

/// Parolanın kurallara uyduğunu kontrol eder (en az 16 karakter, büyük/rakam/özel, zayıf listede değil).
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_LENGTH {
        return Err(Error::Password(
            "Password must be at least 16 characters".into(),
        ));
    }
    let lowered = password.to_lowercase();
    let has_weak = WEAK_PASSWORDS
        .iter()
        .any(|w| lowered.as_bytes().ct_eq(w.as_bytes()).unwrap_u8() == 1);
    if has_weak {
        return Err(Error::Password("Password is in weak password list".into()));
    }
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    if !has_upper || !has_digit || !has_special {
        return Err(Error::Password(
            "Password must contain uppercase, digit and special character".into(),
        ));
    }
    Ok(())
}

/// Saldırganların sözlüklerinde ilk denenen kökler (küçük harfle aranır).
static COMMON_ROOTS: &[&str] = &[
    "password",
    "parola",
    "sifre",
    "şifre",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "seviyorum",
    "istanbul",
    "ankara",
    "izmir",
    "galatasaray",
    "fenerbahce",
    "besiktas",
    "trabzon",
    "turkiye",
    "abc123",
    "monkey",
    "dragon",
    "sunshine",
    "football",
    "master",
    "shadow",
    "superman",
];

/// Yeni şifreleme için parola kuralı: temel kurallar + tahmin edilebilir kalıpların reddi
/// (yıl, tekrar, ardışık dizi, klavye sırası, yaygın kök). Çözmede uygulanmaz: eski dosyalar açılabilir kalır.
/// 7+ kelimelik parola cümleleri (`passgen` biçimi) bu kalıp kontrolünden muaftır.
pub fn validate_new_password(password: &str) -> Result<()> {
    validate_password(password)?;
    // CLI bağlam soneki (`|CTX:<hex>`) rastgeledir; yalnızca kullanıcının yazdığı kısım incelenir.
    let base = password.split("|CTX:").next().unwrap_or(password);
    let words = base
        .split(['-', ' '])
        .filter(|w| w.len() >= 3 && w.chars().all(char::is_alphabetic))
        .count();
    if words >= 7 {
        return Ok(());
    }
    if let Some(reason) = guessable_pattern(&base.to_lowercase()) {
        return Err(Error::Password(format!(
            "Password is guessable ({}). Use `kaotik passgen` for a strong passphrase",
            reason
        )));
    }
    Ok(())
}

fn guessable_pattern(p: &str) -> Option<&'static str> {
    if COMMON_ROOTS.iter().any(|w| p.contains(w)) {
        return Some("common word");
    }
    let b: Vec<char> = p.chars().collect();
    let year = b.windows(4).any(|w| {
        w.iter().all(char::is_ascii_digit) && matches!((w[0], w[1]), ('1', '9') | ('2', '0'))
    });
    if year {
        return Some("contains a year");
    }
    if b.windows(4).any(|w| w.iter().all(|c| *c == w[0])) {
        return Some("repeated characters");
    }
    let run = |w: &[char], d: i32| w.windows(2).all(|p| p[1] as i32 - p[0] as i32 == d);
    if b.windows(4)
        .any(|w| w.iter().all(char::is_ascii_alphanumeric) && (run(w, 1) || run(w, -1)))
    {
        return Some("sequential characters");
    }
    for row in ["qwertyuiop", "asdfghjkl", "zxcvbnm"] {
        if (0..row.len() - 3).any(|i| p.contains(&row[i..i + 4])) {
            return Some("keyboard pattern");
        }
    }
    None
}

static WORDLIST: &str = include_str!("bip39_english.txt");

/// Rastgele parola cümlesi (BIP39 İngilizce listesi, 2048 kelime = kelime başına 11 bit).
/// 9 kelime ≈ 99 bit: Argon2id (256 MiB) ile kaba kuvvet fiziksel olarak imkânsız düzeydedir.
/// Sonuna iki rakam eklenir ki parola kurallarını (büyük harf, rakam, özel karakter) da sağlasın.
pub fn generate_passphrase(words: usize) -> Result<String> {
    let list: Vec<&str> = WORDLIST.lines().collect();
    debug_assert_eq!(list.len(), 2048);
    let mut buf = vec![0u8; words * 2 + 1];
    crate::crypto::random_bytes(&mut buf)?;
    let mut out: Vec<String> = buf[..words * 2]
        .chunks(2)
        .map(|c| {
            // 2048 = 2^11: alt 11 bit yansız seçim verir.
            let w = list[(u16::from_le_bytes([c[0], c[1]]) & 0x7FF) as usize];
            let mut cs = w.chars();
            cs.next()
                .map(|f| f.to_ascii_uppercase().to_string() + cs.as_str())
                .unwrap_or_default()
        })
        .collect();
    out.push(format!("{:02}", buf[words * 2] % 100));
    Ok(out.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guessable_passwords_rejected_for_new_files() {
        for p in [
            "Istanbul2024!!!!",
            "MyPassword!!7xQz",
            "Kx7#mQv2!Lr1234z",
            "Kx7#mQv2!Lraaaaz",
            "Kx7#qwerty!Lr9$W",
            "Kx7#mQv2!Lr9$Wz4|CTX:",
        ] {
            let r = validate_new_password(p);
            assert!(r.is_err() || p.ends_with("|CTX:"), "{} accepted", p);
        }
        assert!(validate_new_password("Kx7#mQv2!Lr9$Wz4").is_ok());
        assert!(validate_new_password("Kx7#mQv2!Lr9$Wz4|CTX:1234aaaa2024ffffA1!").is_ok());
    }

    #[test]
    fn passphrase_is_valid_and_random() {
        let a = generate_passphrase(9).unwrap();
        assert_eq!(a.split('-').count(), 10);
        assert!(validate_new_password(&a).is_ok(), "{}", a);
        assert_ne!(a, generate_passphrase(9).unwrap());
    }
}
