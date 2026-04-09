//! Kaotik CLI: encrypt, decrypt, verify + advanced security modes.
use clap::{Parser, Subcommand};
use kaotik::{
    decrypt_aes, decrypt_kaotik, decrypt_kyber, encrypt_aes, encrypt_kaotik, encrypt_kyber,
    verify_file,
};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

mod cli_ext;

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
        #[arg(long)]
        gps: Option<String>,
        #[arg(long)]
        time_slot: Option<String>,
        #[arg(long)]
        mutating: bool,
        #[arg(long)]
        not_after_unix: Option<u64>,
        #[arg(long)]
        emergency_key: Option<String>,
        #[arg(long)]
        entropy_poison: bool,
        #[arg(long)]
        polymorphic: bool,
        #[arg(long)]
        quantum_canary: bool,
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
        #[arg(long)]
        gps: Option<String>,
        #[arg(long)]
        time_slot: Option<String>,
        #[arg(long)]
        mutating: bool,
        #[arg(long)]
        honey: bool,
        #[arg(long)]
        emergency_key: Option<String>,
        #[arg(long)]
        entropy_poison: bool,
        #[arg(long)]
        polymorphic: bool,
        #[arg(long)]
        quantum_canary: bool,
    },
    /// Dosya yapısını doğrula (header + format); parola gerekmez.
    Verify {
        #[arg(short, long)]
        input: String,
    },
    /// Chaffing: gerçek payload etrafına sahte paketler ekler.
    ChaffPack {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        password: String,
        #[arg(long, default_value_t = 64)]
        fake_packets: u32,
    },
    /// Winnowing: chaff paketlerden gerçek payload'u çıkarır.
    ChaffUnpack {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        password: String,
    },
    /// Şifreli veriyi taşıyıcı dosyanın bitlerine gömer.
    StegoEmbed {
        #[arg(long)]
        carrier: String,
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        password: String,
    },
    /// Taşıyıcı dosyadan gömülü veriyi çıkarır.
    StegoExtract {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        password: String,
    },
    /// Dead-man switch zarfı uygular.
    SealSwitch {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        not_after_unix: u64,
        #[arg(long)]
        emergency_key: Option<String>,
    },
    /// Dead-man switch zarfını açar.
    UnsealSwitch {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        emergency_key: Option<String>,
    },
    /// Plausible deniability container üretir: decoy + hidden katman.
    PlausibleCreate {
        #[arg(long)]
        decoy_input: String,
        #[arg(long)]
        hidden_input: String,
        #[arg(short, long)]
        output: String,
        #[arg(long)]
        decoy_password: String,
        #[arg(long)]
        hidden_password: String,
    },
    /// Plausible container açar; hangi parola verilirse o katman açılır.
    PlausibleOpen {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short, long)]
        password: String,
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
    let state_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            password,
            mode,
            key_out,
            gps,
            time_slot,
            mutating,
            not_after_unix,
            emergency_key,
            entropy_poison,
            polymorphic,
            quantum_canary,
        } => {
            let env_pass = std::env::var(PASSWORD_ENV).ok();
            let mut pwd = get_password(env_pass, password)?;
            let mutation_seed = if mutating {
                cli_ext::read_mutation_seed(&state_dir)
            } else {
                None
            };
            let mut ctx_pwd = cli_ext::derive_context_password(
                &pwd,
                gps.as_deref(),
                time_slot.as_deref(),
                mutation_seed.as_ref(),
            );

            let mut input_reader: Box<dyn Read> = if input == "-" {
                Box::new(io::stdin())
            } else {
                Box::new(File::open(&input)?)
            };

            let result = (|| -> kaotik::Result<()> {
                let mut tmp_out = Vec::new();
                match mode.to_lowercase().as_str() {
                    "kaotik" => encrypt_kaotik(&mut input_reader, &mut tmp_out, &ctx_pwd)?,
                    "aes" => encrypt_aes(&mut input_reader, &mut tmp_out, &ctx_pwd)?,
                    "kyber" => {
                        let path = key_out.ok_or_else(|| kaotik::Error::Format("Kyber requires --key-out".into()))?;
                        let mut key_file = File::create(&path)?;
                        encrypt_kyber(&mut input_reader, &mut tmp_out, &ctx_pwd, &mut key_file)?;
                    }
                    _ => {
                        return Err(kaotik::Error::Format(
                            "Invalid mode. Use kaotik, aes, or kyber.".into(),
                        ));
                    }
                }

                let final_blob = if let Some(expiry) = not_after_unix {
                    cli_ext::deadman_wrap(&tmp_out, expiry, emergency_key.as_deref())
                } else {
                    tmp_out
                };

                let mut wrapped = final_blob;
                if quantum_canary {
                    wrapped = cli_ext::quantum_canary_wrap(&wrapped, &ctx_pwd);
                }
                if entropy_poison {
                    wrapped = cli_ext::entropy_poison_wrap(&wrapped, &ctx_pwd)
                        .map_err(kaotik::Error::Format)?;
                }
                if polymorphic {
                    wrapped = cli_ext::polymorphic_wrap(&wrapped, &ctx_pwd)
                        .map_err(kaotik::Error::Format)?;
                }

                if output == "-" {
                    io::stdout().write_all(&wrapped)?;
                } else {
                    let mut out = File::create(&output)?;
                    out.write_all(&wrapped)?;
                }
                Ok(())
            })();

            if mutating && output != "-" && result.is_ok() {
                let _ = cli_ext::update_mutation_seed(&state_dir, &output);
            }

            pwd.zeroize();
            ctx_pwd.zeroize();
            result
        }
        Commands::Decrypt {
            input,
            output,
            password,
            mode,
            key_file,
            gps,
            time_slot,
            mutating,
            honey,
            emergency_key,
            entropy_poison,
            polymorphic,
            quantum_canary,
        } => {
            let env_pass = std::env::var(PASSWORD_ENV).ok();
            let mut pwd = get_password(env_pass, password)?;
            let mutation_seed = if mutating {
                cli_ext::read_mutation_seed(&state_dir)
            } else {
                None
            };
            let mut ctx_pwd = cli_ext::derive_context_password(
                &pwd,
                gps.as_deref(),
                time_slot.as_deref(),
                mutation_seed.as_ref(),
            );

            let mut input_blob = Vec::new();
            if input == "-" {
                io::stdin().read_to_end(&mut input_blob)?;
            } else {
                File::open(&input)?.read_to_end(&mut input_blob)?;
            }

            let result = (|| -> kaotik::Result<Vec<u8>> {
                let mut outer = input_blob.clone();
                if polymorphic {
                    outer = cli_ext::polymorphic_unwrap(&outer, &ctx_pwd)
                        .map_err(kaotik::Error::Format)?;
                }
                if entropy_poison {
                    outer = cli_ext::entropy_poison_unwrap(&outer, &ctx_pwd)
                        .map_err(kaotik::Error::Format)?;
                }
                if quantum_canary {
                    outer = cli_ext::quantum_canary_unwrap(&outer, &ctx_pwd)
                        .map_err(kaotik::Error::Format)?;
                }

                let unwrapped = cli_ext::deadman_unwrap(&outer, emergency_key.as_deref())
                    .map_err(kaotik::Error::Format)?;
                let mut reader = io::Cursor::new(unwrapped);
                let mut out_buf = Vec::new();

                match mode.to_lowercase().as_str() {
                    "kaotik" => decrypt_kaotik(&mut reader, &mut out_buf, &ctx_pwd)?,
                    "aes" => decrypt_aes(&mut reader, &mut out_buf, &ctx_pwd)?,
                    "kyber" => {
                        let path = key_file.ok_or_else(|| kaotik::Error::Format("Kyber requires --key-file".into()))?;
                        let mut key_read = File::open(&path)?;
                        decrypt_kyber(&mut reader, &mut out_buf, &ctx_pwd, &mut key_read)?;
                    }
                    _ => {
                        return Err(kaotik::Error::Format(
                            "Invalid mode. Use kaotik, aes, or kyber.".into(),
                        ));
                    }
                }
                Ok(out_buf)
            })();

            let final_output = match result {
                Ok(v) => v,
                Err(_) if honey => cli_ext::generate_honey_decoy(&input_blob, &ctx_pwd, &mode),
                Err(e) => {
                    pwd.zeroize();
                    ctx_pwd.zeroize();
                    return Err(e);
                }
            };

            if output == "-" {
                io::stdout().write_all(&final_output)?;
            } else {
                let mut out = File::create(&output)?;
                out.write_all(&final_output)?;
            }

            pwd.zeroize();
            ctx_pwd.zeroize();
            Ok(())
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
        Commands::ChaffPack {
            input,
            output,
            password,
            fake_packets,
        } => {
            let payload = std::fs::read(&input)?;
            let packed = cli_ext::chaff_pack(&payload, &password, fake_packets)
                .map_err(kaotik::Error::Format)?;
            std::fs::write(&output, packed)?;
            Ok(())
        }
        Commands::ChaffUnpack {
            input,
            output,
            password,
        } => {
            let blob = std::fs::read(&input)?;
            let payload = cli_ext::chaff_unpack(&blob, &password).map_err(kaotik::Error::Format)?;
            std::fs::write(&output, payload)?;
            Ok(())
        }
        Commands::StegoEmbed {
            carrier,
            input,
            output,
            password,
        } => {
            let carrier_bytes = std::fs::read(&carrier)?;
            let secret = std::fs::read(&input)?;
            let stego = cli_ext::stego_embed(&carrier_bytes, &secret, &password)
                .map_err(kaotik::Error::Format)?;
            std::fs::write(&output, stego)?;
            Ok(())
        }
        Commands::StegoExtract {
            input,
            output,
            password,
        } => {
            let stego = std::fs::read(&input)?;
            let payload = cli_ext::stego_extract(&stego, &password).map_err(kaotik::Error::Format)?;
            std::fs::write(&output, payload)?;
            Ok(())
        }
        Commands::SealSwitch {
            input,
            output,
            not_after_unix,
            emergency_key,
        } => {
            let blob = std::fs::read(&input)?;
            let wrapped = cli_ext::deadman_wrap(&blob, not_after_unix, emergency_key.as_deref());
            std::fs::write(&output, wrapped)?;
            Ok(())
        }
        Commands::UnsealSwitch {
            input,
            output,
            emergency_key,
        } => {
            let blob = std::fs::read(&input)?;
            let unwrapped =
                cli_ext::deadman_unwrap(&blob, emergency_key.as_deref()).map_err(kaotik::Error::Format)?;
            std::fs::write(&output, unwrapped)?;
            Ok(())
        }
        Commands::PlausibleCreate {
            decoy_input,
            hidden_input,
            output,
            decoy_password,
            hidden_password,
        } => {
            let decoy_plain = std::fs::read(&decoy_input)?;
            let hidden_plain = std::fs::read(&hidden_input)?;
            let container = cli_ext::plausible_create(
                &decoy_plain,
                &hidden_plain,
                &decoy_password,
                &hidden_password,
            )
            .map_err(kaotik::Error::Format)?;
            std::fs::write(&output, container)?;
            Ok(())
        }
        Commands::PlausibleOpen {
            input,
            output,
            password,
        } => {
            let blob = std::fs::read(&input)?;
            let opened = cli_ext::plausible_open(&blob, &password)
                .map_err(kaotik::Error::Format)?;
            std::fs::write(&output, opened)?;
            Ok(())
        }
    }
}
