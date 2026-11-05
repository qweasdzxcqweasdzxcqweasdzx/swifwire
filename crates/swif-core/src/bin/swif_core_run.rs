//! Tiny embed demo: core_start → SOCKS until Ctrl+C / --seconds N.

use std::env;
use std::thread;
use std::time::Duration;

use swif_core::{core_start, core_status, core_stop};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    let mut args = env::args().skip(1);
    let config_path = args.next().expect("usage: swif_core_run <config.json> [--seconds N]");
    let mut seconds = 0u64;
    while let Some(a) = args.next() {
        if a == "--seconds" {
            seconds = args
                .next()
                .unwrap_or_else(|| "0".into())
                .parse()
                .unwrap_or(0);
        }
    }
    let cfg = std::fs::read_to_string(&config_path).expect("read config");
    let h = core_start(&cfg).expect("core_start");
    println!("{}", core_status(&h).unwrap());
    if seconds > 0 {
        thread::sleep(Duration::from_secs(seconds));
    } else {
        // block until killed
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }
    core_stop(h);
}
