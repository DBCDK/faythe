extern crate openssl;
extern crate regex;

use self::openssl::asn1::Asn1TimeRef;
use self::openssl::nid::Nid;
use self::openssl::x509::{X509NameEntryRef, X509};

use crate::config::VaultPersistSpec;
use crate::config::{ConfigContainer, FaytheConfig, Zone};
use crate::file::FileError;
use crate::kube::KubeError;
use crate::vault;
use crate::vault::VaultError;
use crate::{file, kube, log};
use acme_lib::order::NewOrder;
use acme_lib::persist::Persist;
use acme_lib::{Account, Certificate};
use regex::Regex;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt::Formatter;
use std::path::PathBuf;
pub type CertName = String;

#[derive(Debug, Clone, Serialize)]
pub struct CertSpec {
    pub name: CertName,
    pub cn: DNSName,
    pub sans: HashSet<DNSName>,
    pub persist_spec: PersistSpec,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct DNSName {
    pub name: String,
    pub is_wildcard: bool
}

impl std::convert::TryFrom<&String> for DNSName {
    type Error = SpecError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new("^(\\*\\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$").unwrap();
        }
        if RE.is_match(value) {
            Ok(DNSName{
                name: String::from(value.clone().trim_start_matches("*.")),
                is_wildcard: value.starts_with("*.")
            })
        } else {
            Err(SpecError::InvalidHostname)
        }
    }
}

impl DNSName {

    fn generic_checks<'l>(&self, config: &'l FaytheConfig) -> Result<&'l Zone, SpecError> {
        let zone: &'l Zone = self.find_zone(&config)?;
        if zone.issue_wildcard_certs && self.is_wildcard {
            return Err(SpecError::WildcardHostnameNotAllowedWithAutoWildcardIssuingEnabled)
        }
        Ok(zone)
    }

    // will return *.example.com for wildcard name: *.example.com
    pub fn to_domain_string(&self) -> String {
        self.to_string(true)
    }

    // will return example.com for wildcard name: *.example.com
    pub fn to_parent_domain_string(&self) -> String {
        self.to_string(false)
    }

    pub fn to_wildcard(&self) -> Result<DNSName, SpecError> {
        let mut iter = self.name.split('.');
        let first = iter.next();
        match first {
            Some(_) => {
                let parts: Vec<&str> = iter.collect();
                Ok(DNSName {
                    name: parts.join("."),
                    is_wildcard: true
                })
            },
            None => Err(SpecError::InvalidHostname)
        }
    }

    /*
        Since Faythe now supports multiple authoritative zones, we might end up with authoritative zones like:
          1. k8s.dbc.dk
          2. dbc.dk

        Trouble is then to select the appropriate DNS-zone for challenge responses.
        The basic idea is to match the zone name that is the longest suffix of the hostname.
        Examples:

        "foo.k8s.dbc.dk" matches "k8s.dbc.dk", not "dbc.dk", because the zone string .k8s.dbc.dk is the longest suffix of foo.k8s.dbc.dk.
        "foo.dbc.dk" will not match "k8s.dbc.dk" but will match "dbc.dk", because ".k8s.dbc.dk" is not a suffix of "foo.dbc.dk" at all, but ".dbc.dk" is.
        "dk" will not match any of the zones.

        See test case "common::test_find_zone()" for more examples
    */
    pub fn find_zone<'l>(&self, config: &'l FaytheConfig) -> Result<&'l Zone, SpecError> {
        let domain_string = format!(".{}",self.to_parent_domain_string());
        let res = &config.zones.iter()
            .filter(|(k,_)| domain_string.ends_with(format!(".{}", k).as_str()))
            .max_by_key(|(k,_)| k.len());
        res.and_then(|(_,z)| Some(z)).ok_or(SpecError::NonAuthoritativeDomain(self.clone()))
    }

    fn to_string(&self, include_asterisk: bool) -> String {
        if self.is_wildcard && include_asterisk {
            format!("*.{name}",name=self.name)
        } else {
            self.name.clone()
        }
    }
}

impl std::fmt::Display for DNSName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.to_domain_string())
    }
}

impl CertSpec {
    pub fn to_acme_order<'l, P>(&self, acc: &Account<P>) -> Result<NewOrder<P>, acme_lib::Error> where P: Persist {
        let mut sans: Vec<String> = Vec::new();
        for s in &self.sans {
            sans.push(s.to_domain_string());
        }
        let sans_: Vec<&str> = sans.iter().map(|s| s.as_str()).collect();
        acc.new_order(&self.cn.to_domain_string().as_str(), sans_.as_slice())
    }
    pub fn get_auth_dns_servers(&self, config: &FaytheConfig) -> Result<HashSet<String>, SpecError> {
        let mut res = HashSet::new();
        res.insert(self.cn.find_zone(&config)?.server.clone());
        for s in &self.sans {
            res.insert(s.find_zone(&config)?.server.clone());
        }
        Ok(res)
    }
    pub fn compare_cn(&self, other: &String) -> bool {
        &self.cn.to_domain_string() == other
    }
    pub fn compare_sans(&self, others: &HashSet<String>) -> bool {
        let spec_sans: HashSet<String> = self.sans.iter().map(|s| s.to_domain_string()).collect();
        let other_sans: HashSet<String> = others.iter().map(|s| s.to_owned()).collect();
        spec_sans == other_sans
    }
}

pub trait Persistable {
    fn persist(&self, cert: Certificate) -> Result<(), PersistError>;
}

#[derive(Debug, Clone, Serialize)]
pub struct KubernetesPersistSpec {
    pub name: String,
    pub namespace: String,
    pub host_label_key: String,
    pub host_label_value: String
}

#[derive(Debug, Clone, Serialize)]
pub struct FilePersistSpec {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf
}

#[derive(Debug, Clone, Serialize)]
pub enum PersistSpec {
    KUBERNETES(KubernetesPersistSpec),
    FILE(FilePersistSpec),
    VAULT(VaultPersistSpec),
    #[allow(dead_code)]
    DONTPERSIST
}

impl Persistable for CertSpec {
    fn persist(&self, cert: Certificate) -> Result<(), PersistError> {
        match &self.persist_spec {
            PersistSpec::KUBERNETES(spec) => Ok(kube::persist(&spec, &cert)?),
            PersistSpec::FILE(spec) => Ok(file::persist(&spec, &cert)?),
            PersistSpec::VAULT(spec) => Ok(vault::persist(&spec, cert)?),
            //PersistSpec::FILE(_spec) => { unimplemented!() },
            PersistSpec::DONTPERSIST => { Ok(()) }
        }
    }
}

impl std::convert::From<KubeError> for PersistError {
    fn from(err: KubeError) -> Self {
        PersistError::Kube(err)
    }
}

#[derive(Debug, Clone)]
pub struct Cert {
    pub cn: String,
    pub sans: HashSet<String>,
    pub valid_from: time::Tm, // always utc
    pub valid_to: time::Tm // always utc
}

impl Cert {
    pub fn parse(pem_bytes: &Vec<u8>) -> Result<Cert, CertState> {
        if pem_bytes.len() == 0 {
            return Err(CertState::Empty)
        }

        match X509::from_pem(&pem_bytes) {
            Ok(x509) => {
                Ok(Cert {
                    cn: Self::get_cn(&x509)?,
                    sans: Self::get_sans(&x509),
                    valid_from: Self::get_timestamp(&x509.not_before())?,
                    valid_to: Self::get_timestamp(&x509.not_after())?
                })
            },
            Err(e) => {
                log::error("failed to parse pem-blob", &e);
                Err(CertState::ParseError)
            }
        }
    }

    fn get_cn(x509: &X509) -> Result<String, CertState> {
        match x509.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
            Some(cn) => Ok(Self::get_string(cn)?),
            None => Err(CertState::ParseError)
        }
    }

    fn get_sans(x509: &X509) -> HashSet<String> {
        let mut out: HashSet<String> = HashSet::new();
        if x509.subject_alt_names().is_some() {
            for n in x509.subject_alt_names().unwrap() {
                let dns_name = n.dnsname();
                if dns_name.is_some() { // ip sans etc. are not supported currently
                    out.insert(String::from(dns_name.unwrap()));
                }
            }
        }
        out
    }

    fn get_string(name_ref: &X509NameEntryRef) -> Result<String, CertState> {
        match name_ref.data().as_utf8() {
            Ok(s) => Ok(s.to_string()),
            _ => Err(CertState::ParseError)
        }
    }

    // #cryhard rust openssl lib doesn't allow for a plain convertion from ASN-time to time::Tm or any
    // other rustlang time type. :( So... We to_string the ASNTime and re-parse it and hope for the best
    fn get_timestamp(time_ref: &Asn1TimeRef) -> Result<time::Tm, time::ParseError> {
        const IN_FORMAT: &str = "%b %e %H:%M:%S %Y %Z"; // May 31 15:21:16 2020 GMT
        time::strptime(&format!("{}", &time_ref), IN_FORMAT)
    }

    pub fn state(&self, config: &FaytheConfig, spec: &CertSpec) -> CertState {
        let now = time::now_utc();
        let state = match self.valid_to {
            to if now > to => CertState::Expired,
            to if now + time::Duration::days(config.renewal_threshold as i64) > to => CertState::ExpiresSoon,
            _ if now < self.valid_from => CertState::NotYetValid,
            to if now >= self.valid_from && now <= to => CertState::Valid,
            _ => CertState::Unknown,
        };

        let state = match &spec {
            s if ! s.compare_cn(&self.cn) => CertState::CNDoesntMatch,
            s if ! s.compare_sans(&self.sans) => CertState::SANSDontMatch,
            _ => state
        };

        log::data(&format!("State for cert: {}", &self.cn), &state);
        state
    }

    pub fn is_valid(&self, config: &FaytheConfig, spec: &CertSpec) -> bool {
        self.state(config, spec) == CertState::Valid
    }
}

pub enum PersistError {
    Kube(KubeError),
    File(FileError),
    Vault(VaultError),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum CertState {
    Empty,
    ParseError,
    Expired,
    ExpiresSoon,
    NotYetValid,
    Valid,
    CNDoesntMatch,
    SANSDontMatch,
    Unknown,
}

pub trait ValidityVerifier {
    fn is_valid(&self, config: &FaytheConfig, spec: &CertSpec) -> bool;
}

pub trait CertSpecable: IssueSource {
    fn to_cert_spec(&self, config: &ConfigContainer) -> Result<CertSpec, SpecError>;
    fn touch(&self, config: &ConfigContainer) -> Result<(), TouchError>;
    fn should_retry(&self, config: &ConfigContainer) -> bool;
}

pub trait IssueSource {
    fn get_raw_cn(&self) -> String;
    fn get_raw_sans(&self) -> HashSet<String>;

    fn get_computed_cn(&self, config: &FaytheConfig) -> Result<DNSName, SpecError> {
        let cn = DNSName::try_from(&self.get_raw_cn())?;
        let zone = cn.generic_checks(&config)?;
        Ok(match zone.issue_wildcard_certs {
            true => cn.to_wildcard()?,
            false => cn
        })
    }
    fn get_computed_sans(&self, config: &FaytheConfig) -> Result<HashSet<DNSName>, SpecError> {
        let mut out = HashSet::new();
        let cn = DNSName::try_from(&self.get_raw_cn())?;

        let raw_sans = self.get_raw_sans();
        let zone = cn.generic_checks(&config)?;
        if zone.issue_wildcard_certs && raw_sans.len() > 0 {
            return Err(SpecError::SansNotSupportedWithAutoWildcardIssuingEnabled)
        }

        for s in &raw_sans {
            let s_ = DNSName::try_from(s)?;
            s_.generic_checks(&config)?;
            out.insert(s_);
        }
        out.insert(self.get_computed_cn(&config)?);
        Ok(out)
    }
}
#[derive(Debug, Clone, Serialize)]
pub enum SpecError {
    InvalidHostname,
    NonAuthoritativeDomain(DNSName),
    WildcardHostnameNotAllowedWithAutoWildcardIssuingEnabled,
    SansNotSupportedWithAutoWildcardIssuingEnabled,
    InvalidConfig
}

#[derive(Debug, Clone)]
pub enum TouchError {
    RecentlyTouched,
    Failed,
}

impl std::convert::From<SpecError> for TouchError {
    fn from(_: SpecError) -> Self {
        TouchError::Failed
    }
}

impl std::convert::From<time::ParseError> for CertState {
    fn from(_: time::ParseError) -> Self {
        CertState::ParseError
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::kube::Ingress;
    use crate::file::FileSpec;
    use std::collections::HashMap;
    use crate::set;
    use super::DNSName;
    use crate::config::{KubeMonitorConfig, FileMonitorConfig, MonitorConfig};

    const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%z"; // 2019-10-09T11:50:22+0200

    pub fn create_test_file_config(issue_wildcard_certs: bool) -> ConfigContainer {
        let file_monitor_configs = FileMonitorConfig {
            directory: "/tmp".to_string(),
            specs: vec!(create_filespec("host")),
            prune: false
        };
        let zones = create_zones(issue_wildcard_certs);
        let faythe_config = FaytheConfig{
            metrics_port: 9105,
            kube_monitor_configs: vec!(),
            file_monitor_configs: vec![file_monitor_configs.clone()],
            vault_monitor_configs: vec![],
            lets_encrypt_url: String::new(),
            lets_encrypt_proxy: None,
            lets_encrypt_email: String::new(),
            val_dns_servers: Vec::new(),
            monitor_interval: 0,
            renewal_threshold: 30,
            issue_grace: 0,
            zones
        };

        ConfigContainer{
            faythe_config,
            monitor_config: MonitorConfig::File(file_monitor_configs)
        }
    }

    fn create_zones(issue_wildcard_certs: bool) -> HashMap<String, Zone> {
        let mut zones = HashMap::new();
        zones.insert(String::from("unit.test"), Zone{
            server: String::from("ns.unit.test"),
            key: String::new(),
            challenge_suffix: None,
            issue_wildcard_certs
        });
        zones.insert(String::from("alternative.unit.test"), Zone{
            server: String::from("ns.alternative.unit.test"),
            key: String::new(),
            challenge_suffix: None,
            issue_wildcard_certs
        });
        zones.insert(String::from("suffixed.unit.test"), Zone{
            server: String::from("ns.suffixed.unit.test"),
            key: String::new(),
            challenge_suffix: Some(String::from("acme.example.com")),
            issue_wildcard_certs
        });
        zones
    }

    pub fn create_test_kubernetes_config(issue_wildcard_certs: bool) -> ConfigContainer {
        let kube_monitor_config = KubeMonitorConfig {
            secret_namespace: String::new(),
            secret_hostlabel: String::new(),
            touch_annotation: None,
            wildcard_cert_prefix: String::from("wild---card")
        };
        let zones = create_zones(issue_wildcard_certs);
        let faythe_config = FaytheConfig{
            metrics_port: 9105,
            kube_monitor_configs: vec![kube_monitor_config.clone()],
            file_monitor_configs: vec![],
            vault_monitor_configs: vec![],
            lets_encrypt_url: String::new(),
            lets_encrypt_proxy: None,
            lets_encrypt_email: String::new(),
            val_dns_servers: Vec::new(),
            monitor_interval: 0,
            renewal_threshold: 30,
            issue_grace: 0,
            zones
        };

        ConfigContainer{
            faythe_config,
            monitor_config: MonitorConfig::Kube(kube_monitor_config)
        }
    }

    fn create_test_certspec(cn: &str, sans: HashSet<String>) -> CertSpec {

        let name = cn.to_string();
        let cn = DNSName::try_from(&cn.to_string()).unwrap();
        let sans: HashSet<DNSName> = sans.iter().map(|s| DNSName::try_from(&s.to_string()).unwrap()).collect();
        let persist_spec = PersistSpec::DONTPERSIST; 

        CertSpec {
            name,
            cn,
            sans,
            persist_spec
        }
    }

    fn create_ingress(host: &str) -> Ingress {
        Ingress{
            name: "test".to_string(),
            namespace: "test".to_string(),
            touched: time::empty_tm(),
            hosts: [host.to_string()].to_vec(),
        }
    }

    fn create_filespec(host: &str) -> FileSpec {
        FileSpec{
            name: "test".to_string(),
            cn: host.to_string(),
            sans: HashSet::new(),
            sub_directory: None,
            cert_file_name: None,
            key_file_name: None,
        }
    }

    #[test]
    fn test_valid_pem() {
        let bytes = include_bytes!("../test/longlived.pem");
        let cert = Cert::parse(&bytes.to_vec()).unwrap();

        let cn = "cn.longlived";
        let sans = set![cn, "san1.longlived", "san2.longlived"];

        assert_eq!(cert.cn, cn);
        assert_eq!(cert.sans, sans);

        /*
            Not Before: Dec  1 11:42:07 2020 GMT
            Not After : Nov 24 11:42:07 2050 GMT
        */
        assert_eq!(cert.valid_from, time::strptime("2020-12-01T11:42:07+0000", TIME_FORMAT).unwrap());
        assert_eq!(cert.valid_to, time::strptime("2050-11-24T11:42:07+0000", TIME_FORMAT).unwrap());

        let config = create_test_kubernetes_config(false).faythe_config;
        let spec = create_test_certspec(cn, sans);

        assert_eq!(cert.state(&config, &spec), CertState::Valid);
        assert!(cert.is_valid(&config, &spec));
    }

    #[test]
    fn test_cn_mismatch() {
        let bytes = include_bytes!("../test/longlived.pem");
        let cert = Cert::parse(&bytes.to_vec()).unwrap();

        let cn = "cn.shortlived";
        let sans = set!["san1.longlived", "san2.longlived"];

        /*
            Not Before: Dec  1 11:42:07 2020 GMT
            Not After : Nov 24 11:42:07 2050 GMT
        */
        assert_eq!(cert.valid_from, time::strptime("2020-12-01T11:42:07+0000", TIME_FORMAT).unwrap());
        assert_eq!(cert.valid_to, time::strptime("2050-11-24T11:42:07+0000", TIME_FORMAT).unwrap());

        let config = create_test_kubernetes_config(false).faythe_config;
        let spec = create_test_certspec(cn, sans);

        assert_eq!(cert.state(&config, &spec), CertState::CNDoesntMatch);
        assert!(!cert.is_valid(&config, &spec));
    }

    #[test]
    fn test_sans_mismatch() {
        let bytes = include_bytes!("../test/longlived.pem");
        let cert = Cert::parse(&bytes.to_vec()).unwrap();

        /*
            Not Before: Dec  1 11:42:07 2020 GMT
            Not After : Nov 24 11:42:07 2050 GMT
        */
        assert_eq!(cert.valid_from, time::strptime("2020-12-01T11:42:07+0000", TIME_FORMAT).unwrap());
        assert_eq!(cert.valid_to, time::strptime("2050-11-24T11:42:07+0000", TIME_FORMAT).unwrap());

        let cn = "cn.longlived";
        let sans = set![cn, "san1.longlived", "san2.shortlived"];
        let config = create_test_kubernetes_config(false).faythe_config;
        let spec = create_test_certspec(cn, sans);

        assert_eq!(cert.state(&config, &spec), CertState::SANSDontMatch);
        assert!(!cert.is_valid(&config, &spec));

        let cn = "cn.longlived";
        let sans = set![cn, "san1.longlived", "san2.longlived", "san3.longlived"];
        let config = create_test_kubernetes_config(false).faythe_config;
        let spec = create_test_certspec(cn, sans);

        assert_eq!(cert.state(&config, &spec), CertState::SANSDontMatch);
        assert!(!cert.is_valid(&config, &spec));

        let cn = "cn.longlived";
        let sans = set!["san2.longlived", "san1.longlived", cn]; // order of sans doesn't matter
        let config = create_test_kubernetes_config(false).faythe_config;
        let spec = create_test_certspec(cn, sans);

        assert_eq!(cert.state(&config, &spec), CertState::Valid);
        assert!(cert.is_valid(&config, &spec));

        let cn = "cn.longlived";
        let sans = set![cn, "san2.longlived", "san1.longlived", "san2.longlived"]; // same san can be passed multiple times to the san set
        let config = create_test_kubernetes_config(false).faythe_config;
        let spec = create_test_certspec(cn, sans);

        assert_eq!(cert.state(&config, &spec), CertState::Valid);
        assert!(cert.is_valid(&config, &spec));
    }

    #[test]
    fn test_expired_pem() {
        let bytes = include_bytes!("../test/expired.pem");
        let cert = Cert::parse(&bytes.to_vec()).unwrap();

        let cn = "cn.expired";
        let sans = set![cn, "san1.expired", "san2.expired"];

        assert_eq!(cert.cn, cn);
        assert_eq!(cert.sans, sans);

        /*
            Not Before: Dec  1 11:41:19 2020 GMT
            Not After : Dec  2 11:41:19 2020 GMT
        */
        assert_eq!(cert.valid_from, time::strptime("2020-12-01T11:41:19+0000", TIME_FORMAT).unwrap());
        assert_eq!(cert.valid_to, time::strptime("2020-12-02T11:41:19+0000", TIME_FORMAT).unwrap());

        let config = create_test_kubernetes_config(false).faythe_config;
        let spec = create_test_certspec(cn, sans);

        assert!(cert.state(&config, &spec) == CertState::ExpiresSoon || cert.state(&config, &spec) == CertState::Expired);
        assert!(!cert.is_valid(&config, &spec));
    }

    #[test]
    fn test_find_zone() {
        {
            let config = create_test_kubernetes_config(false);

            let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.unit.wrongtest")).unwrap();
            let z = host.find_zone(&config.faythe_config);
            assert!(z.is_err());

            let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.foo.test")).unwrap();
            let z = host.find_zone(&config.faythe_config);
            assert!(z.is_err());

            let host: DNSName = DNSName::try_from(&String::from("test")).unwrap();
            let z = host.find_zone(&config.faythe_config);
            assert!(z.is_err());

            let host: DNSName = DNSName::try_from(&String::from("google.com")).unwrap();
            let z = host.find_zone(&config.faythe_config);
            assert!(z.is_err());

            let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.unit.test")).unwrap();
            let z = host.find_zone(&config.faythe_config);
            assert!(z.is_ok());
        }

        {
            let config = create_test_kubernetes_config(false);

            let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.unit.test")).unwrap();
            let z = host.find_zone(&config.faythe_config).unwrap();
            assert_eq!(z.server, "ns.unit.test");

            let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.alternative.unit.test")).unwrap();
            let z = host.find_zone(&config.faythe_config).unwrap();
            assert_eq!(z.server, "ns.alternative.unit.test");

            let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.other-alternative.unit.test")).unwrap();
            let z = host.find_zone(&config.faythe_config).unwrap();
            assert_eq!(z.server, "ns.unit.test");

            let host: DNSName = DNSName::try_from(&String::from("unit.test")).unwrap();
            let z = host.find_zone(&config.faythe_config).unwrap();
            assert_eq!(z.server, "ns.unit.test");
        }
    }

    #[test]
    fn test_wildcard_san_mismatch_regression() {
        let bytes = include_bytes!("../test/wildcard.pem");
        let cert = Cert::parse(&bytes.to_vec()).unwrap();

        let cn = "*.unit.test";
        let sans = set![cn];

        assert_eq!(cert.cn, cn);
        assert_eq!(cert.sans, sans);

        let container = create_test_kubernetes_config(true);
        let config = &container.faythe_config;
        let spec = create_ingress("foo.unit.test").to_cert_spec(&container).unwrap();

        assert!(cert.state(&config, &spec) == CertState::Valid);
        assert!(cert.is_valid(&config, &spec));

        let container = create_test_file_config(true);
        let config = &container.faythe_config;
        let spec = create_filespec("foo.unit.test").to_cert_spec(&container).unwrap();

        assert!(cert.state(&config, &spec) == CertState::Valid);
        assert!(cert.is_valid(&config, &spec));
    }
}
