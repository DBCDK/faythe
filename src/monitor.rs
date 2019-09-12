extern crate time;

use std::thread;
use std::time::Duration;

use crate::config::ConfigContainer;
use crate::file;
use crate::kube;
use crate::log;
use crate::vault::VaultError;

use std::result::Result;

use std::sync::mpsc::Sender;

use crate::common::{CertName, CertSpec};
use crate::common::{CertSpecable, ValidityVerifier};
use crate::file::FileError;
use crate::kube::KubeError;
use crate::vault::VaultCert;
use std::collections::HashMap;
use std::prelude::v1::Vec;

use crate::metrics;
use crate::metrics::MetricsType;

pub fn monitor_k8s(config: ConfigContainer, tx: Sender<CertSpec>) {
    log::info("k8s monitoring-started");
    let monitor_config = config.get_kube_monitor_config().unwrap();
    loop {
        let _ = || -> Result<(), KubeError> {
            let ingresses = kube::get_ingresses(&monitor_config)?;
            let secrets = kube::get_secrets(&monitor_config)?;
            inspect(&config, &tx, &ingresses, secrets);
            Ok(())
        }();
        thread::sleep(Duration::from_millis(config.faythe_config.monitor_interval));
    }
}

pub fn monitor_files(config: ConfigContainer, tx: Sender<CertSpec>) {
    log::info("file monitoring-started");
    let monitor_config = config.get_file_monitor_config().unwrap();
    loop {
        let _ = || -> Result<(), FileError> {
            let certs = file::read_certs(&monitor_config)?;
            inspect(&config, &tx, &monitor_config.specs, certs);
            Ok(())
        }();
        thread::sleep(Duration::from_millis(config.faythe_config.monitor_interval));
    }
}

pub fn monitor_vault(config: ConfigContainer, tx: Sender<CertSpec>) {
    log::info("vault monitoring-started");
    // just crash if we cant authenticate vault client on startup
    let monitor_config = config.get_vault_monitor_config().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _ = rt
        .block_on(async {
            crate::vault::authenticate(
                &monitor_config.role_id_path,
                &monitor_config.secret_id_path,
                &monitor_config.vault_addr,
            )
            .await
        })
        .map_err(|_| std::process::exit(1));
    // enter monitor loop
    loop {
        let _ = || -> Result<(), VaultError> {
            let certs: HashMap<CertName, VaultCert> = crate::vault::list(&monitor_config)?;
            inspect(&config, &tx, &monitor_config.specs, certs);
            Ok(())
        }();
        thread::sleep(Duration::from_millis(config.faythe_config.monitor_interval));
    }
}

fn inspect<CS, VV>(
    config: &ConfigContainer,
    tx: &Sender<CertSpec>,
    objects: &Vec<CS>,
    certs: HashMap<CertName, VV>,
) where
    CS: CertSpecable,
    VV: ValidityVerifier,
{
    let faythe_config = &config.faythe_config;
    for o in objects {
        let spec = o.to_cert_spec(&config);
        match &spec {
            s if s.is_ok() && o.should_retry(&config) => {
                let spec = s.as_ref().unwrap();

                let should_issue = match certs.get(&spec.name) {
                    Some(cert) => !cert.is_valid(&faythe_config, &spec),
                    None => {
                        log::data("no matching cert found for, first-time issue", &spec.name);
                        true
                    }
                };

                match o.touch(&config) {
                    Ok(_) => {
                        log::data("touched", &spec.name); //TODO: improve logging
                        if should_issue {
                            log::data("(re-)issuing", &spec.name); //TODO: improve logging
                            tx.send(spec.to_owned()).unwrap()
                        }
                    }
                    Err(e) => {
                        log::error("failed to touch object, bailing out.", &e);
                        metrics::new_event(&spec.name, MetricsType::Failure);
                    }
                };
            }
            Ok(_) => {} // not time for issuing
            Err(e) => log::error("certspec invalid", &e),
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::common::tests::*;
    use crate::common::{Cert, DNSName};
    use crate::kube::{Ingress, Secret};
    use crate::mpsc;
    use crate::mpsc::{Receiver, Sender};
    use std::collections::HashSet;
    use std::ops::Add;

    fn create_channel() -> (Sender<CertSpec>, Receiver<CertSpec>) {
        mpsc::channel()
    }

    fn create_ingress(host: &String) -> Vec<Ingress> {
        [Ingress {
            name: "test".to_string(),
            namespace: "test".to_string(),
            touched: time::empty_tm(),
            hosts: [host.clone()].to_vec(),
        }]
        .to_vec()
    }

    fn create_secret(host: &String, valid_days: i64) -> Secret {
        let mut sans = HashSet::new();
        sans.insert(host.clone());
        Secret {
            name: String::from("test"),
            namespace: String::from("test"),
            cert: Cert {
                cn: host.clone(),
                sans,
                valid_from: time::now_utc(),
                valid_to: time::now_utc().add(time::Duration::days(valid_days)),
            },
            key: vec![],
        }
    }

    #[test]
    fn test_normal_new_issue() {
        let host = String::from("host1.subdivision.unit.test");

        let config = create_test_kubernetes_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || inspect(&config, &tx, &ingresses, secrets));

        let spec = rx.recv().unwrap();
        assert_eq!(spec.cn.to_domain_string(), host);
        thread.join().unwrap();
    }

    #[test]
    fn test_wildcard_new_issue() {
        let host = String::from("host1.subdivision.unit.test");
        let name = String::from("wild---card.subdivision.unit.test");

        let config = create_test_kubernetes_config(true);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || inspect(&config, &tx, &ingresses, secrets));

        let spec = rx.recv().unwrap();
        assert_eq!(spec.name, name);
        assert_eq!(
            spec.cn.to_domain_string(),
            String::from("*.subdivision.unit.test")
        );
        thread.join().unwrap();
    }

    #[test]
    fn test_wildcard_host_in_ingress() {
        let host = String::from("*.subdivision.unit.test");

        let config = create_test_kubernetes_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || inspect(&config, &tx, &ingresses, secrets));

        assert!(rx.try_recv().is_err()); // it is not allowed to ask for a wildcard cert in k8s ingress specs
        thread.join().unwrap();
    }

    #[test]
    fn test_non_authoritative_domain() {
        let host = String::from("host1.subdivision.unit.wrongtest");

        let config = create_test_kubernetes_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || inspect(&config, &tx, &ingresses, secrets));

        assert!(rx.recv().is_err()); // faythe must know an authoritative ns server for the domain in question
        thread.join().unwrap();
    }

    #[test]
    fn test_normal_renewal() {
        let host = String::from("renewal1.subdivision.unit.test");

        let config = create_test_kubernetes_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let mut secrets: HashMap<String, kube::Secret> = HashMap::new();
        secrets.insert(host.clone(), create_secret(&host, 20));

        let thread = thread::spawn(move || inspect(&config, &tx, &ingresses, secrets));

        let spec = rx.recv().unwrap();
        assert_eq!(spec.cn.to_domain_string(), host);
        thread.join().unwrap();
    }

    #[test]
    fn test_not_yet_time_for_renewal() {
        let host = String::from("renewal2.subdivision.unit.test");
        let name = host.clone();

        let config = create_test_kubernetes_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let mut secrets: HashMap<String, kube::Secret> = HashMap::new();
        secrets.insert(name, create_secret(&host, 40));

        let thread = thread::spawn(move || inspect(&config, &tx, &ingresses, secrets));

        assert!(rx.recv().is_err()); // there should be nothing to issue
        thread.join().unwrap();
    }

    #[test]
    fn test_wildcard_not_yet_time_for_renewal() {
        use std::convert::TryFrom;

        let host = DNSName::try_from(&String::from("renewal2.subdivision.unit.test")).unwrap();
        let name = String::from("wild---card.subdivision.unit.test");

        let config = create_test_kubernetes_config(true);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host.to_domain_string());
        let mut secrets: HashMap<String, kube::Secret> = HashMap::new();
        secrets.insert(
            name,
            create_secret(&host.to_wildcard().unwrap().to_domain_string(), 40),
        );

        let thread = thread::spawn(move || inspect(&config, &tx, &ingresses, secrets));

        assert!(rx.recv().is_err()); // there should be nothing to issue
        thread.join().unwrap();
    }
}
