extern crate trust_dns_resolver;

use std::result::Result;
use crate::FaytheConfig;

use std::convert::From;

use crate::log;
use crate::common::{CertSpec, DnsName, SpecError};
use crate::config::Zone;
use self::trust_dns_resolver::TokioAsyncResolver;
use self::trust_dns_resolver::error::{ResolveError,ResolveErrorKind};
use std::string::String;

use crate::exec::ExecErrorInfo;

use crate::config::{ChallengeDriver as DriverConfig};

mod nsupdate;
mod webhook;

#[derive(Debug)]
pub enum DnsError {
    #[allow(dead_code)] // Debug only
    Exec(ExecErrorInfo),
    #[allow(dead_code)] // Debug only
    IO(std::io::Error),
    OutputFormat,
    #[allow(dead_code)] // Debug only
    ResolveError(ResolveError),
    #[allow(dead_code)] // Debug only
    WrongAnswer(String),
    WrongSpec,
    #[allow(dead_code)] // Debug only
    Reqwest(reqwest::Error),
}

pub trait ChallengeDriver {
    fn add(&self, challenge_host: &String, proof: &String) -> Result<(), DnsError>;
    fn delete(&self, challenge_host: &String) -> Result<(), DnsError>;
}

pub fn add(config: &FaytheConfig, name: &DnsName, proof: &String) -> Result<(), DnsError> {
    let zone = name.find_zone(config)?;
    let challenge_host = challenge_host(name, Some(zone));
    match &zone.challenge_driver {
        DriverConfig::NSUpdate(nsupdate) => {
            nsupdate.add(&challenge_host, proof)
        },
        DriverConfig::NoOp => Ok(()),
        DriverConfig::Webhook(webhook) => {
            webhook.add(&challenge_host, proof)
        }
    }
}

pub fn delete(config: &FaytheConfig, spec: &CertSpec) -> Result<(), DnsError> {
    let zone = spec.cn.find_zone(config)?;
    let host = challenge_host(&spec.cn, Some(zone));
    match &zone.challenge_driver {
        DriverConfig::NSUpdate(nsupdate) => {
            nsupdate.delete(&host)?
        },
        DriverConfig::NoOp => (),
        DriverConfig::Webhook(webhook) => {
            webhook.delete(&host)?
        }
    };
    for s in &spec.sans {
        let zone = s.find_zone(config)?;
        let host = challenge_host(s, Some(zone));
        match &zone.challenge_driver {
            DriverConfig::NSUpdate(nsupdate) => {
                nsupdate.delete(&host)?
            },
            DriverConfig::NoOp => (),
            DriverConfig::Webhook(webhook) => {
                webhook.delete(&host)?
            }
        }
    }
    Ok(())
}

pub async fn query(resolver: &TokioAsyncResolver, host: &DnsName, proof: &String) -> Result<(), DnsError> {
    let challenge_host = challenge_host(host, None);
    match resolver.txt_lookup(&challenge_host).await {
        Ok(res) => {
            let trim_chars: &[_] = &['"', '\n'];
            res.iter().find(|record_set|
                record_set.iter().any(|record| {
                    match String::from_utf8((*record).to_vec()) {
                        Ok(txt) => txt.trim_matches(trim_chars) == proof,
                        Err(_) => false,
                    }
                })
            ).ok_or(DnsError::WrongAnswer(challenge_host.clone())).and(Ok(()))
        },
        Err(e) => {
            match e.kind() {
                ResolveErrorKind::NoRecordsFound{..} => Err(DnsError::WrongAnswer(challenge_host.clone())),
                _ => Err(DnsError::ResolveError(e))
            }
        }
    }
}

fn challenge_host(host: &DnsName, zone: Option<&Zone>) -> String {
    let suffix = match zone {
        Some(zone) => match &zone.challenge_suffix {
            Some(suffix) => format!(".{}", suffix),
            None => String::new()
        }
        None => String::new()
    };
    format!("_acme-challenge.{}{}.", &host.to_parent_domain_string(), &suffix)
}

impl From<std::io::Error> for DnsError {
    fn from(err: std::io::Error) -> DnsError {
        DnsError::IO(err)
    }
}

impl From<std::string::FromUtf8Error> for DnsError {
    fn from(_: std::string::FromUtf8Error) -> DnsError {
        DnsError::OutputFormat
    }
}

impl std::convert::From<ExecErrorInfo> for DnsError {
    fn from(err: ExecErrorInfo) -> Self {
        log::error("Failed to exec dns command", &err);
        DnsError::Exec(err)
    }
}

impl std::convert::From<SpecError> for DnsError {
    fn from(err: SpecError) -> Self {
        log::error("Faythe does not know a dns-server authoritative for", &err);
        DnsError::WrongSpec
    }
}

impl std::convert::From<reqwest::Error> for DnsError {
    fn from(err: reqwest::Error) -> Self {
        log::error("Error with webhook invocation", &err);
        DnsError::Reqwest(err)
    }
}
