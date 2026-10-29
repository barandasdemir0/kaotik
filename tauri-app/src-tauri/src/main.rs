#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use zeroize::Zeroize;

fn normalize_mode(mode: &str) -> Result<&str, String> {
    match mode.to_lowercase().as_str() {
        "kaotik" => Ok("kaotik"),
        "aes" => Ok("aes"),
        "kyber" => Ok("kyber"),
        _ => Err("Invalid mode. Use kaotik, aes, or kyber.".to_string()),
    }
}

/// Çıktıyı önce geçici dosyaya yazar, başarılıysa yerine taşır: hata veya aynı yol seçimi veri kaybettirmez.
fn write_atomically(
    input_path: &str,
    output_path: &str,
    run: impl FnOnce(File, File) -> kaotik::Result<()>,
) -> Result<(), String> {
    let same = std::fs::canonicalize(input_path).ok().is_some_and(|i| std::fs::canonicalize(output_path).ok() == Some(i));
    if same {
        return Err("Output path must differ from input path".to_string());
    }
    let reader = File::open(input_path).map_err(|e| e.to_string())?;
    let tmp = format!("{}.kaotik-tmp", output_path);
    let writer = File::create(&tmp).map_err(|e| e.to_string())?;
    match run(reader, writer) {
        Ok(()) => std::fs::rename(&tmp, output_path).map_err(|e| e.to_string()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn validate_password_cmd(password: String) -> Result<String, String> {
    kaotik::validate_password(&password).map_err(|e| e.to_string())?;
    Ok("Parola politikasi gecerli.".to_string())
}

#[tauri::command]
fn verify_file(input_path: String) -> Result<String, String> {
    let reader = File::open(&input_path).map_err(|e| e.to_string())?;
    kaotik::verify_file(reader).map_err(|e| e.to_string())?;
    Ok("OK: file structure valid.".to_string())
}

#[tauri::command]
fn encrypt_file(
    input_path: String,
    output_path: String,
    password: String,
    mode: String,
    key_path: Option<String>,
) -> Result<String, String> {
    let mode = normalize_mode(&mode)?;
    let mut pwd = password;
    let result = write_atomically(&input_path, &output_path, |reader, writer| match mode {
        "kaotik" => kaotik::encrypt_kaotik(reader, writer, &pwd),
        "aes" => kaotik::encrypt_aes(reader, writer, &pwd),
        "kyber" => {
            let key_path = key_path.ok_or_else(|| kaotik::Error::Format("Kyber mode requires key_path".into()))?;
            let mut key_out = File::create(&key_path)?;
            kaotik::encrypt_kyber(reader, writer, &pwd, &mut key_out)
        }
        _ => unreachable!(),
    });
    pwd.zeroize();
    result?;

    Ok(format!("Encrypt tamamlandi. mode={} output={}", mode, output_path))
}

#[tauri::command]
fn decrypt_file(
    input_path: String,
    output_path: String,
    password: String,
    mode: String,
    key_path: Option<String>,
) -> Result<String, String> {
    let mode = normalize_mode(&mode)?;
    let mut pwd = password;
    let result = write_atomically(&input_path, &output_path, |reader, writer| match mode {
        "kaotik" => kaotik::decrypt_kaotik(reader, writer, &pwd),
        "aes" => kaotik::decrypt_aes(reader, writer, &pwd),
        "kyber" => {
            let key_path = key_path.ok_or_else(|| kaotik::Error::Format("Kyber mode requires key_path".into()))?;
            let mut key_reader = File::open(&key_path)?;
            kaotik::decrypt_kyber(reader, writer, &pwd, &mut key_reader)
        }
        _ => unreachable!(),
    });
    pwd.zeroize();
    result?;

    Ok(format!("Decrypt tamamlandi. mode={} output={}", mode, output_path))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            validate_password_cmd,
            verify_file,
            encrypt_file,
            decrypt_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running kaotik tauri application");
}
