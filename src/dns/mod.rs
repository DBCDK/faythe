extern crate trust_dns_resolver;

use std::result::Result;
use crate::FaytheConfig;

use std::convert::From;

use crate::log;
use crate::common::{CertSpec, DNSName, SpecError};
use crate::config::Zone;
use self::trust_dns_resolver::Resolver;
use self::trust_dns_resolver::error::{ResolveError,ResolveErrorKind};
use std::string::String;

use crate::exec::ExecErrorInfo;

use crate::config::{ChallengeDriver as DriverConfig};

mod nsupdate;

#[derive(Debug)]
pub enum DNSError {
    Exec(ExecErrorInfo),
    IO(std::io::Error),
    OutputFormat,
    ResolveError(ResolveError),
    WrongAnswer(String),
    WrongSpec
}

pub trait ChallengeDriver {
    fn add(&self, challenge_host: &String, proof: &String) -> Result<(), DNSError>;
    fn delete(&self, challenge_host: &String) -> Result<(), DNSError>;
}

pub fn add(config: &FaytheConfig, name: &DNSName, proof: &String) -> Result<(), DNSError> {
    let zone = name.find_zone(&config)?;
    let challenge_host = challenge_host(name, Some(&zone));
    match &zone.challenge_driver {
        DriverConfig::NSUpdate(nsupdate) => {
            nsupdate.add(&challenge_host, proof)
        },
        DriverConfig::NoOp => Ok(())
    }
}

pub fn delete(config: &FaytheConfig, spec: &CertSpec) -> Result<(), DNSError> {
    let zone = spec.cn.find_zone(&config)?;
    let host = challenge_host(&spec.cn, Some(&zone));
    match &zone.challenge_driver {
        DriverConfig::NSUpdate(nsupdate) => {
            nsupdate.delete(&host)?
        },
        DriverConfig::NoOp => ()
    };
    for s in &spec.sans {
        let zone = s.find_zone(&config)?;
        let host = challenge_host(s, Some(&zone));
        match &zone.challenge_driver {
            DriverConfig::NSUpdate(nsupdate) => {
                nsupdate.delete(&host)?
            },
            DriverConfig::NoOp => ()
        }
    }
    Ok(())
}

pub fn query(resolver: &Resolver, host: &DNSName, proof: &String) -> Result<(), DNSError> {
    let c_host = challenge_host(host, None);
    match resolver.txt_lookup(&c_host) {
        Ok(res) => {
            let trim_chars: &[_] = &['"', '\n'];
            res.iter().find(|rr|
                rr.iter().find(|r| {
                    match String::from_utf8((*r).to_vec()) {
                        Ok(txt) => &txt.trim_matches(trim_chars) == proof,
                        Err(_) => false,
                    }
                }).is_some()
            ).ok_or(DNSError::WrongAnswer(c_host.clone())).and(Ok(()))
        },
        Err(e) => {
            match e.kind() {
                ResolveErrorKind::NoRecordsFound{..} => Err(DNSError::WrongAnswer(c_host.clone())),
                _ => Err(DNSError::ResolveError(e))
            }
        }
    }
}

fn challenge_host(host: &DNSName, zone: Option<&Zone>) -> String {
    let suffix = match zone {
        Some(z) => match &z.challenge_suffix {
            Some(s) => format!(".{}", s),
            None => String::new()
        }
        None => String::new()
    };
    format!("_acme-challenge.{}{}.", &host.to_parent_domain_string(), &suffix)
}

impl From<std::io::Error> for DNSError {
    fn from(e: std::io::Error) -> DNSError {
        DNSError::IO(e)
    }
}

impl From<std::string::FromUtf8Error> for DNSError {
    fn from(_: std::string::FromUtf8Error) -> DNSError {
        DNSError::OutputFormat
    }
}

impl std::convert::From<ExecErrorInfo> for DNSError {
    fn from(err: ExecErrorInfo) -> Self {
        log::error("Failed to exec dns command", &err);
        DNSError::Exec(err)
    }
}

impl std::convert::From<SpecError> for DNSError {
    fn from(err: SpecError) -> Self {
        log::error("Faythe does not know a dns-server authoritative for", &err);
        DNSError::WrongSpec
    }
}
