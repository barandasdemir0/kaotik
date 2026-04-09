//! Kaotik CLI: encrypt, decrypt, verify.
use clap::{Parser, Subcommand};
use kaotik::{
    decrypt_aes, decrypt_kaotik, decrypt_kyber, encrypt_aes, encrypt_kaotik, encrypt_kyber,
    verify_file,
};
use std::fs::File;
use std::io::{self, Read, Write};
use zeroize::Zeroize;

const PASSWORD_ENV: &str = "KAOTIK_PASSWORD";

#[derive(Parser)]
#[command(name = "kaotik")]
#[command(version)]
#[command(about = "Kaotik Sifreleme - platform-independent encryption (kaotik, aes, kyber)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Şifrele: --input, --output, --password (veya KAOTIK_PASSWORD), --mode kaotik|aes|kyber
    Encrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long, default_value = "kaotik")]
        mode: String,
        #[arg(long)]
        key_out: Option<String>,
    },
    /// Çöz: --input, --output, --password, --mode; kyber için --key-file
    Decrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long, default_value = "kaotik")]
        mode: String,
        #[arg(long)]
        key_file: Option<String>,
    },
    /// Dosya yapısını doğrula (header + format); parola gerekmez.
    Verify {
        #[arg(short, long)]
        input: String,
    },
}

fn get_password(env_pass: Option<String>, arg_pass: Option<String>) -> kaotik::Result<String> {
    if let Some(pwd) = env_pass.filter(|s| !s.is_empty()) {
        return Ok(pwd);
    }
    let pwd = arg_pass.ok_or_else(|| kaotik::Error::Format("Missing --password or KAOTIK_PASSWORD".into()))?;
    eprintln!("Warning: --password on command line may be visible. Prefer {}.", PASSWORD_ENV);
    Ok(pwd)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> kaotik::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt { input, output, password, mode, key_out } => {
            let env_pass = std::env::var(PASSWORD_ENV).ok();
            let mut pwd = get_password(env_pass, password)?;
            let reader: Box<dyn Read> = if input == "-" {
                Box::new(io::stdin())
            } else {
                Box::new(File::open(&input)?)
            };
            let writer: Box<dyn Write> = if output == "-" {
                Box::new(io::stdout())
            } else {
                Box::new(File::create(&output)?)
            };
            let result = match mode.to_lowercase().as_str() {
                "kaotik" => encrypt_kaotik(reader, writer, &pwd),
                "aes" => encrypt_aes(reader, writer, &pwd),
                "kyber" => {
                    let path = key_out.ok_or_else(|| kaotik::Error::Format("Kyber requires --key-out".into()))?;
                    let mut key_file = File::create(&path)?;
                    encrypt_kyber(reader, writer, &pwd, &mut key_file)
                }
                _ => Err(kaotik::Error::Format("Invalid mode. Use kaotik, aes, or kyber.".into())),
            };
            pwd.zeroize();
            result
        }
        Commands::Decrypt { input, output, password, mode, key_file } => {
            let env_pass = std::env::var(PASSWORD_ENV).ok();
            let mut pwd = get_password(env_pass, password)?;
            let reader: Box<dyn Read> = if input == "-" {
                Box::new(io::stdin())
            } else {
                Box::new(File::open(&input)?)
            };
            let writer: Box<dyn Write> = if output == "-" {
                Box::new(io::stdout())
            } else {
                Box::new(File::create(&output)?)
            };
            let result = match mode.to_lowercase().as_str() {
                "kaotik" => decrypt_kaotik(reader, writer, &pwd),
                "aes" => decrypt_aes(reader, writer, &pwd),
                "kyber" => {
                    let path = key_file.ok_or_else(|| kaotik::Error::Format("Kyber requires --key-file".into()))?;
                    let mut key_read = File::open(&path)?;
                    decrypt_kyber(reader, writer, &pwd, &mut key_read)
                }
                _ => Err(kaotik::Error::Format("Invalid mode. Use kaotik, aes, or kyber.".into())),
            };
            pwd.zeroize();
            result
        }
        Commands::Verify { input } => {
            let reader: Box<dyn Read> = if input == "-" {
                Box::new(io::stdin())
            } else {
                Box::new(File::open(&input)?)
            };
            verify_file(reader)?;
            println!("OK: file structure valid.");
            Ok(())
        }
    }
}
