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
