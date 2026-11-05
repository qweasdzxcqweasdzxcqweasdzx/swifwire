//! Commercial console shell: Start/Stop via swif-core-run (live SOCKS core).

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9443")]
    server: String,
    #[arg(long, default_value = "server.pub")]
    pub_file: PathBuf,
    #[arg(long, default_value = "127.0.0.1:10808")]
    socks: String,
    #[arg(long, default_value = "tls13_stable")]
    mask: String,
    #[arg(long, default_value = "lab-cert.der.json")]
    tls_material: PathBuf,
    #[arg(long)]
    core_bin: Option<PathBuf>,
    #[arg(long, default_value = "client.runtime.json")]
    config_out: PathBuf,
}

fn find_core(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    for c in [
        PathBuf::from("swif-core-run.exe"),
        PathBuf::from("target/release/swif-core-run.exe"),
        PathBuf::from("target/debug/swif-core-run.exe"),
    ] {
        if c.exists() {
            return Ok(c);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("swif-core-run.exe");
            if p.exists() {
                return Ok(p);
            }
        }
    }
    bail!("swif-core-run.exe not found; pass --core-bin")
}

fn write_config(args: &Args) -> Result<()> {
    let pub_hex = std::fs::read_to_string(&args.pub_file)
        .with_context(|| format!("read {}", args.pub_file.display()))?
        .trim()
        .to_string();
    if pub_hex.len() != 64 {
        bail!("server.pub must be 64 hex chars");
    }
    let tls = args.tls_material.display().to_string().replace('\\', "/");
    let json = format!(
        "{{\n  \"server_addr\": \"{}\",\n  \"server_static_pub_hex\": \"{}\",\n  \"mask_profile\": \"{}\",\n  \"socks_listen\": \"{}\",\n  \"tls_material_path\": \"{}\",\n  \"start_runtime\": true,\n  \"route_mode\": \"global\"\n}}\n",
        args.server, pub_hex, args.mask, args.socks, tls
    );
    std::fs::write(&args.config_out, json)?;
    Ok(())
}

fn start_core(args: &Args, bin: &PathBuf) -> Result<Child> {
    write_config(args)?;
    let c = Command::new(bin)
        .arg(&args.config_out)
        .arg("--seconds")
        .arg("86400")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(c)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    let args = Args::parse();
    let core = find_core(args.core_bin.clone())?;
    println!("SwifWire commercial shell");
    println!("core={} socks={}", core.display(), args.socks);
    println!("[1] Start  [2] Stop  [q] Quit");
    let mut child: Option<Child> = None;
    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        match line.trim() {
            "1" => {
                if child.is_some() {
                    println!("already running");
                    continue;
                }
                match start_core(&args, &core) {
                    Ok(c) => {
                        println!("started pid={} config={}", c.id(), args.config_out.display());
                        child = Some(c);
                    }
                    Err(e) => println!("start failed: {e:#}"),
                }
            }
            "2" => {
                if let Some(mut c) = child.take() {
                    let _ = c.kill();
                    println!("stopped");
                } else {
                    println!("not running");
                }
            }
            "q" | "Q" => {
                if let Some(mut c) = child.take() {
                    let _ = c.kill();
                }
                break;
            }
            _ => println!("unknown"),
        }
    }
    Ok(())
}
