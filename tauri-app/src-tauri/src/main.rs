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
    let reader = File::open(&input_path).map_err(|e| e.to_string())?;
    let writer = File::create(&output_path).map_err(|e| e.to_string())?;

    let mut pwd = password;
    let result = match mode {
        "kaotik" => kaotik::encrypt_kaotik(reader, writer, &pwd),
        "aes" => kaotik::encrypt_aes(reader, writer, &pwd),
        "kyber" => {
            let key_path = key_path.ok_or_else(|| "Kyber mode requires key_path".to_string())?;
            let mut key_out = File::create(&key_path).map_err(|e| e.to_string())?;
            kaotik::encrypt_kyber(reader, writer, &pwd, &mut key_out)
        }
        _ => unreachable!(),
    };
    pwd.zeroize();
    result.map_err(|e| e.to_string())?;

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
    let reader = File::open(&input_path).map_err(|e| e.to_string())?;
    let writer = File::create(&output_path).map_err(|e| e.to_string())?;

    let mut pwd = password;
    let result = match mode {
        "kaotik" => kaotik::decrypt_kaotik(reader, writer, &pwd),
        "aes" => kaotik::decrypt_aes(reader, writer, &pwd),
        "kyber" => {
            let key_path = key_path.ok_or_else(|| "Kyber mode requires key_path".to_string())?;
            let mut key_reader = File::open(&key_path).map_err(|e| e.to_string())?;
            kaotik::decrypt_kyber(reader, writer, &pwd, &mut key_reader)
        }
        _ => unreachable!(),
    };
    pwd.zeroize();
    result.map_err(|e| e.to_string())?;

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
