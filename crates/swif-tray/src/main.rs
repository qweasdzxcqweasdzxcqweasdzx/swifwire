//! Console lab shell: Start / Stop swif-cli SOCKS without GUI deps.
//! Windows NotifyIcon: `scripts/tray-lab.ps1`.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Result};
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9443")]
    server: String,
    #[arg(long, default_value = "server.pub")]
    pub_file: PathBuf,
    #[arg(long, default_value = "127.0.0.1:11080")]
    socks: String,
    #[arg(long, default_value = "null_tcp")]
    mask: String,
    #[arg(long)]
    cli: Option<PathBuf>,
}

fn find_cli(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    for c in [
        PathBuf::from("swif-cli.exe"),
        PathBuf::from("target/debug/swif-cli.exe"),
        PathBuf::from("target/release/swif-cli.exe"),
    ] {
        if c.exists() {
            return Ok(c);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("swif-cli.exe");
            if p.exists() {
                return Ok(p);
            }
        }
    }
    bail!("swif-cli.exe not found; pass --cli")
}

fn start_cli(args: &Args, cli: &PathBuf) -> Result<Child> {
    let c = Command::new(cli)
        .arg("--server")
        .arg(&args.server)
        .arg("--pub-file")
        .arg(&args.pub_file)
        .arg("--socks")
        .arg(&args.socks)
        .arg("--mask")
        .arg(&args.mask)
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
    let cli = find_cli(args.cli.clone())?;
    println!("SwifWire tray-shell (console)");
    println!("cli={}", cli.display());
    println!("[1] Start SOCKS  [2] Stop  [q] Quit");
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
                match start_cli(&args, &cli) {
                    Ok(c) => {
                        println!("started pid={}", c.id());
                        child = Some(c);
                    }
                    Err(e) => println!("start failed: {e}"),
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
