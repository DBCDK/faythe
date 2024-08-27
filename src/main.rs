#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;

extern crate clap;

use clap::{arg, command};

use std::{process, thread};

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};

use crate::common::CertSpec;
use crate::config::{ConfigContainer, FaytheConfig, MonitorConfig};

use dbc_rust_modules::{exec, log};

mod common;
mod config;
mod dns;
mod file;
mod issuer;
mod kube;
mod metrics;
mod monitor;
mod vault;

#[macro_export]
macro_rules! set {
    ( $( $x:expr ),* ) => {
        {
            let mut set = std::collections::HashSet::new();
            $(
                set.insert($x.to_string());
            )*
            set
        }
    };
}

const APP_NAME: &str = env!("CARGO_PKG_NAME");

fn main() {
    env_logger::init();
    log::init(APP_NAME.to_string()).unwrap();

    let args = command!()
        .arg(
            arg!(configcheck: "Parses Faythe config file and exits")
                .long("config-check")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            arg!(config: "Path to Faythe config file (JSON)")
                .help("Path to Faythe config file (JSON)")
                .required(true),
        );

    let m = args.get_matches();

    let config_check = m.get_one::<bool>("configcheck").unwrap();
    let config_file = m.get_one::<String>("config").unwrap().to_owned();
    let config = config::parse_config_file(&config_file);
    match config {
        Ok(c) => {
            if !config_check {
                run(&c);
            }
        }
        Err(e) => {
            eprintln!("config-file parse error: {}", &e);
            process::exit(1);
        }
    }
}

fn run(config: &FaytheConfig) {
    let (tx, rx): (Sender<CertSpec>, Receiver<CertSpec>) = mpsc::channel();

    let mut threads = Vec::new();
    for c in &config.kube_monitor_configs {
        let container = ConfigContainer {
            faythe_config: config.clone(),
            monitor_config: MonitorConfig::Kube(c.to_owned()),
        };
        let tx_ = tx.clone();
        threads.push(thread::spawn(move || monitor::monitor_k8s(container, tx_)));
    }
    for c in &config.file_monitor_configs {
        let container = ConfigContainer {
            faythe_config: config.clone(),
            monitor_config: MonitorConfig::File(c.to_owned()),
        };
        let tx_ = tx.clone();
        threads.push(thread::spawn(move || {
            monitor::monitor_files(container, tx_)
        }));
    }
    for c in &config.vault_monitor_configs {
        let container = ConfigContainer {
            faythe_config: config.clone(),
            monitor_config: MonitorConfig::Vault(c.to_owned()),
        };
        let tx_ = tx.clone();
        threads.push(thread::spawn(move || {
            // Spawning the runtime for each (OS-)thread is redundant, but
            // minimally invasive to the rest of the main setup.
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(monitor::monitor_vault(container, tx_))
        }));
    }
    let config_ = config.clone();
    threads.push(thread::spawn(move || issuer::process(config_, rx)));

    if threads.len() < 2 {
        panic!(
            "No monitors started! Did you forget to add monitor configuration to the config file?"
        )
    }

    let metrics_port = config.metrics_port;
    metrics::serve(metrics_port);
    for t in threads {
        t.join().unwrap();
    }
}
