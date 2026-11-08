//! Pack tooling: generate trust key, sign pack, dump ClientHello intent.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use swif_crypto::PackSigningKey;
use swif_mask::{
    build_client_hello_record, client_hello_intent_json, ja3_hash_from_record,
    ja3_string_from_record, sign_pack_value, verify_and_load, QuicInitialTemplate, QuicStableHints,
    TlsPackHints,
};

#[derive(Parser, Debug)]
#[command(name = "swif-pack")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Write a new ed25519 pack signing key (32 raw bytes) + hex pubkey.
    GenKey {
        #[arg(long, default_value = "pack.key")]
        key: PathBuf,
        #[arg(long, default_value = "pack.pub")]
        pub_out: PathBuf,
    },
    /// Sign unsigned pack JSON (signature field replaced).
    Sign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "ops-1")]
        key_id: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a signed pack against trust pubkey hex file or 64-hex string.
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        trust: String,
    },
    /// Print client_hello_intent JSON for a profile inside a pack.
    Intent {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long, default_value = "tls13_stable")]
        profile: String,
    },
    /// Emit a SQI1 base64 blob from structured Initial fields.
    Sqi1 {
        #[arg(long, default_value_t = 1)]
        version: u32,
        #[arg(long, default_value_t = 8)]
        dcid_len: u8,
        #[arg(long, default_value_t = 0)]
        scid_len: u8,
    },
    /// Build crafted ClientHello (pack extension order) and print JA3 lab digests.
    Ja3 {
        #[arg(long, default_value = "packs/example-pack.dev.json")]
        pack: PathBuf,
        #[arg(long, default_value = "tls13_stable")]
        profile: String,
        #[arg(long, default_value = "cdn.example.com")]
        sni: String,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> anyhow::Result<()> {
    match args.cmd {
        Cmd::GenKey { key, pub_out } => {
            let sk = PackSigningKey::generate();
            std::fs::write(&key, sk.to_bytes())?;
            let hex = hex::encode(sk.verifying_key().to_bytes());
            std::fs::write(&pub_out, &hex)?;
            println!("wrote {} / {} trust={}", key.display(), pub_out.display(), hex);
        }
        Cmd::Sign {
            input,
            key,
            key_id,
            output,
        } => {
            let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&input)?)?;
            let kb = std::fs::read(&key)?;
            if kb.len() != 32 {
                anyhow::bail!("key must be 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&kb);
            let sk = PackSigningKey::from_bytes(arr);
            let signed = sign_pack_value(raw, &sk, &key_id)?;
            std::fs::write(&output, serde_json::to_vec_pretty(&signed)?)?;
            println!("signed → {}", output.display());
        }
        Cmd::Verify { pack, trust } => {
            let trust_hex = if std::path::Path::new(&trust).exists() {
                std::fs::read_to_string(&trust)?
            } else {
                trust
            };
            let raw = hex::decode(trust_hex.trim())?;
            if raw.len() != 32 {
                anyhow::bail!("trust pub must be 32 bytes hex");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            let vk = swif_crypto::PackVerifyingKey::from_bytes(arr)?;
            let bytes = std::fs::read(&pack)?;
            let p = verify_and_load(&bytes, &vk)?;
            println!("OK pack_id={} profiles={}", p.pack_id, p.profiles.len());
        }
        Cmd::Intent { pack, profile } => {
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&pack)?)?;
            // Intent dump does not require verify (ops preview).
            let profiles = v["profiles"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("no profiles"))?;
            let p = profiles
                .iter()
                .find(|x| x["id"].as_str() == Some(profile.as_str()))
                .ok_or_else(|| anyhow::anyhow!("profile not found"))?;
            let mp: swif_mask::MaskProfile = serde_json::from_value(p.clone())?;
            let hints = TlsPackHints::from_mask_profile(&mp);
            let q = QuicStableHints::from_mask_profile(&mp);
            println!("{}", client_hello_intent_json(&hints));
            eprintln!(
                "quic_initial_template={} alpn={:?}",
                q.has_initial_template, q.alpn
            );
        }
        Cmd::Ja3 { pack, profile, sni } => {
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&pack)?)?;
            let profiles = v["profiles"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("no profiles"))?;
            let p = profiles
                .iter()
                .find(|x| x["id"].as_str() == Some(profile.as_str()))
                .ok_or_else(|| anyhow::anyhow!("profile not found"))?;
            let mp: swif_mask::MaskProfile = serde_json::from_value(p.clone())?;
            let hints = TlsPackHints::from_mask_profile(&mp);
            let rec = build_client_hello_record(&hints, &sni);
            let ja3 = ja3_string_from_record(&rec).ok_or_else(|| anyhow::anyhow!("ja3 parse"))?;
            let hash = ja3_hash_from_record(&rec).unwrap();
            println!("ja3_string={ja3}");
            println!("ja3_sha256={hash}");
            println!("ch_record_hex={}", hex::encode(&rec));
            println!("note=craft_encoder_only; dial_tls still rustls (extension_order=false)");
        }
        Cmd::Sqi1 {
            version,
            dcid_len,
            scid_len,
        } => {
            let t = QuicInitialTemplate {
                version,
                dcid_len,
                scid_len,
                ..Default::default()
            };
            println!("{}", t.encode_sqi1_b64());
        }
    }
    Ok(())
}
