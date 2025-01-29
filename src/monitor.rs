use std::time::Duration;

use crate::config::ConfigContainer;
use crate::file;
use crate::log;

use tokio::sync::mpsc::Sender;

use crate::common::{CertName, CertSpec};
use crate::common::{CertSpecable, ValidityVerifier};
use std::collections::HashMap;
use std::prelude::v1::Vec;

use crate::metrics;
use crate::metrics::MetricsType;
#[cfg(test)]
use chrono::Utc;

pub async fn monitor_files(config: ConfigContainer, tx: Sender<CertSpec>) {
    log::info("file monitoring-started");
    let monitor_config = config.get_file_monitor_config().unwrap();
    loop {
        let certs = file::read_certs(monitor_config);
        match certs {
            Ok(certs) => {
                inspect(&config, &tx, &monitor_config.specs, certs).await;
            }
            Err(e) => {
                log::error("monitor: failed to get file certificates, bailing out.", &e);
            }
        };
        tokio::time::sleep(Duration::from_millis(config.faythe_config.monitor_interval)).await;
    }
}

pub async fn monitor_vault(config: ConfigContainer, tx: Sender<CertSpec>) {
    log::info("vault monitoring-started");
    // just crash if we cant authenticate vault client on startup
    let monitor_config = config.get_vault_monitor_config().unwrap();
    crate::vault::authenticate(
                &monitor_config.role_id_path,
                &monitor_config.secret_id_path,
                &monitor_config.vault_addr,
            )
            .await
            .unwrap();
    // enter monitor loop
    loop {
        match crate::vault::list(monitor_config).await {
            Ok(certs) => {
                inspect(&config, &tx, &monitor_config.specs, certs).await;
            }
            Err(e) => {
                log::error("monitor: failed to get vault certificates, bailing out.", &e);
            }
        }
        tokio::time::sleep(Duration::from_millis(config.faythe_config.monitor_interval)).await;
    }
}

async fn inspect<CS, VV>(
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
        let spec = o.to_cert_spec(config);
        match &spec {
            s if s.is_ok() && o.should_retry(config).await => {
                let spec = s.as_ref().unwrap();

                let should_issue = match certs.get(&spec.name) {
                    Some(cert) => !cert.is_valid(faythe_config, spec),
                    None => {
                        log::data("no matching cert found for, first-time issue", &spec.name);
                        true
                    }
                };

                match o.touch(config).await {
                    Ok(_) => {
                        log::data("touched", &spec.name); //TODO: improve logging
                        if should_issue {
                            log::data("(re-)issuing", &spec.name); //TODO: improve logging
                            tx.send(spec.to_owned()).await.map_err(|e| {
                                log::error("failed to send certspec to issue channel", &e);
                                metrics::new_event(&spec.name, MetricsType::Failure);
                            }).unwrap();
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
    use crate::common::Cert;
    use crate::mpsc;
    use crate::mpsc::{Receiver, Sender};
    use std::collections::HashSet;
    use file::{FileCert, FileSpec};
    use tokio::runtime::Runtime;

    fn create_channel() -> (Sender<CertSpec>, Receiver<CertSpec>) {
        mpsc::channel(100)
    }

    fn create_filespec(host: &str) -> Vec<FileSpec> {
        [FileSpec{
            name: host.to_string(),
            cn: host.to_string(),
            sans: HashSet::new(),
            sub_directory: None,
            cert_file_name: None,
            key_file_name: None,
        }]
        .to_vec()
    }

    fn create_filecert(host: &String, valid_days: i64) -> FileCert {
        let mut sans = HashSet::new();
        sans.insert(host.clone());
        FileCert {
            cert: Cert {
                cn: host.clone(),
                sans,
                valid_from: Utc::now(),
                valid_to: Utc::now() + chrono::Duration::days(valid_days),
            }
        }
    }

    #[test]
    fn test_normal_new_issue() {
        let rt = Runtime::new().unwrap();
        let host = String::from("host1.subdivision.unit.test");

        let config = create_test_file_config(false);
        let (tx, mut rx) = create_channel();
        let filespecs = create_filespec(&host);
        let certs: HashMap<String, FileCert> = HashMap::new();
        rt.block_on(inspect(&config, &tx, &filespecs, certs));

        let spec = rt.block_on(rx.recv()).unwrap();
        assert_eq!(spec.cn.to_domain_string(), host);
    }

    #[test]
    fn test_wildcard_new_issue() {
        let rt = Runtime::new().unwrap();
        let host = String::from("will-be-substituted-with-wildcard.subdivision.unit.test");

        let config = create_test_file_config(true);
        let (tx, mut rx) = create_channel();
        let filespecs = create_filespec(&host);
        let certs: HashMap<String, FileCert> = HashMap::new();
        rt.block_on(inspect(&config, &tx, &filespecs, certs));

        let spec = rt.block_on(rx.recv()).unwrap();
        assert_eq!(spec.name, host);
        assert_eq!(
            spec.cn.to_domain_string(),
            String::from("*.subdivision.unit.test")
        );
    }

    #[test]
    fn test_non_authoritative_domain() {
        let rt = Runtime::new().unwrap();
        let host = String::from("host1.subdivision.unit.wrongtest");

        let config = create_test_file_config(false);
        let (tx, mut rx) = create_channel();
        let filespecs = create_filespec(&host);
        let certs: HashMap<String, FileCert> = HashMap::new();
        rt.block_on(inspect(&config, &tx, &filespecs, certs));

        // This is fragile and racy, we're signalling NonAuthorativeDomain by
        // _not_ getting a spec back here
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_normal_renewal() {
        let rt = Runtime::new().unwrap();
        let host = String::from("renewal1.subdivision.unit.test");

        let config = create_test_file_config(false);
        let (tx, mut rx) = create_channel();
        let filespecs = create_filespec(&host);
        let mut certs: HashMap<String, FileCert> = HashMap::new();
        certs.insert(host.clone(), create_filecert(&host, 20));

        rt.block_on(inspect(&config, &tx, &filespecs, certs));

        let spec = rx.try_recv().unwrap();
        assert_eq!(spec.cn.to_domain_string(), host);
    }

    #[test]
    fn test_not_yet_time_for_renewal() {
        let rt = Runtime::new().unwrap();
        let host = String::from("renewal2.subdivision.unit.test");

        let config = create_test_file_config(false);
        let (tx, mut rx) = create_channel();
        let filespecs = create_filespec(&host);
        let mut certs: HashMap<String, FileCert> = HashMap::new();
        certs.insert(host.clone(), create_filecert(&host, 40));

        rt.block_on(inspect(&config, &tx, &filespecs, certs));

        // This is fragile and racy, we're signalling issuance not happening by
        // _not_ getting a spec back here
        assert!(rx.try_recv().is_err()); // there should be nothing to issue
    }

    #[test]
    fn test_wildcard_not_yet_time_for_renewal() {
        let rt = Runtime::new().unwrap();

        let host = String::from("*.subdivision.unit.test");

        let config = create_test_file_config(false);
        let (tx, mut rx) = create_channel();
        let filespecs = create_filespec(&host);
        let mut certs: HashMap<String, FileCert> = HashMap::new();
        certs.insert(
            host.clone(),
            create_filecert(&host, 40),
        );

        rt.block_on(inspect(&config, &tx, &filespecs, certs));

        // This is fragile and racy, we're signalling issuance not happening by
        // _not_ getting a spec back here
        assert!(rx.try_recv().is_err()); // there should be nothing to issue
    }
}
