
use std::time::Duration;

use crate::{dns, FaytheConfig, common};
use crate::log;

use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::error::TryRecvError;
use std::collections::{VecDeque, HashSet, HashMap};

use acme_lib::{ClientConfig, Directory, DirectoryUrl, create_rsa_key};
use acme_lib::persist::MemoryPersist;

use crate::common::{CertSpec, Persistable, PersistError, DnsName};
use acme_lib::order::{Auth, NewOrder};
use std::prelude::v1::Vec;

use serde_json::json;
use std::convert::TryFrom;
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};
use trust_dns_resolver::config::{ResolverConfig, NameServerConfigGroup, ResolverOpts};
use trust_dns_resolver::error::ResolveErrorKind;
use std::net::IpAddr;
use tokio::sync::RwLock;
use std::fmt::Debug;

use crate::metrics;
use crate::metrics::MetricsType;

use chrono::Utc;

pub async fn process(faythe_config: FaytheConfig, mut rx: Receiver<CertSpec>) {

    let mut queue: VecDeque<IssueOrder> = VecDeque::new();
    let resolvers = init_resolvers(&faythe_config).await.unwrap();
    RESOLVERS.write().await.inner = resolvers;

    log::info("processing-started");
    loop {
        let res = rx.try_recv();
        match res {
            Ok(cert_spec) => {
                if ! queue.iter().any(|o: &IssueOrder| o.spec.name == cert_spec.name) {
                    match setup_challenge(&faythe_config, &cert_spec) {
                        Ok(order) => queue.push_back(order),
                        Err(e) => {
                            log::info(format!("failed to setup challenge for host: {host}, error: {error:?}", host = cert_spec.cn, error = e).as_str());
                            metrics::new_event(&cert_spec.name, MetricsType::Failure);
                        }
                    };
                } else {
                    log::data("similar cert-spec is already in the issuing queue", &cert_spec)
                }
            },
            Err(TryRecvError::Disconnected) => panic!("channel disconnected"),
            Err(_) => {}
        }

        let queue_check = check_queue(&mut queue).await;
        if queue_check.is_err() {
            log::info("check queue err");
            log::info(&format!("{:?}", queue_check));
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn check_queue(queue: &mut VecDeque<IssueOrder>) -> Result<(), IssuerError> {
    match queue.pop_front() {
        Some(mut order) => {
            match validate_challenge(&order).await {
                Ok(_) => {
                    order.inner.refresh()?;
                    if order.inner.is_validated() {
                        let result = order.issue().await;
                        match result {
                            Ok(_) => metrics::new_event(&order.spec.name, MetricsType::Success),
                            Err(_) => metrics::new_event(&order.spec.name, MetricsType::Failure),
                        }
                        result
                    } else {
                        queue.push_back(order);
                        Ok(())
                    }
                },
                Err(e) => match e {
                    IssuerError::Dns(dns::DnsError::WrongAnswer(domain)) => {
                        log::data("Wrong Dns answer", &domain);
                        // Retry for two hours. Propagation on gratisdns is pretty slow.
                        if Utc::now() < order.challenge_time + chrono::Duration::minutes(120) {
                            queue.push_back(order);
                        } else {
                            log::data("giving up validating dns challenge for spec", &order.spec);
                            metrics::new_event(&order.spec.name, MetricsType::Failure);
                        }
                        Ok(())
                    },
                        _ => {
                            metrics::new_event(&order.spec.name, MetricsType::Failure);
                            Err(e)
                        }
                    }
            }
        },
        None => Ok(())
    }
}

async fn validate_challenge(order: &IssueOrder) -> Result<(), IssuerError> {
    for a in &order.authorizations {
        let domain = DnsName::try_from(&String::from(a.domain_name()))?;
        let challenge = a.dns_challenge();
        let proof = challenge.dns_proof();
        let log_data = json!({ "domain": &domain, "proof": &proof });

        {
            let resolvers = RESOLVERS.read().await;

            // TODO: Proper retry logic
            log::info("Validating internally after 20s");

            log::data("Validating auth_dns_servers internally", &log_data);
            for d in &order.auth_dns_servers {
                dns::query(resolvers.get(d).unwrap(), &domain, &proof).await?;
            }
            log::data("Validating val_dns_servers internally", &log_data);
            for d in &order.val_dns_servers {
                dns::query(resolvers.get(d).unwrap(), &domain, &proof).await?;
            }
        }
        log::data("Asking LE to validate", &log_data);
        challenge.validate(5000)?;
    }
    Ok(())
}

fn setup_challenge(config: &FaytheConfig, spec: &CertSpec) -> Result<IssueOrder, IssuerError> {

    // start by deleting any existing challenges here,
    // because we don't want to bother Let's encrypt and their rate limits,
    // in case we have trouble communicating with the NS-server or similar.
    dns::delete(config, spec)?;

    let persist = MemoryPersist::new();
    let url = DirectoryUrl::Other(&config.lets_encrypt_url);

    let cc = match &config.lets_encrypt_proxy {
        Some(proxy) => ClientConfig::with_proxy(proxy.clone()),
        None => ClientConfig::default()
    };
    let dir = Directory::from_url_with_config(persist, url, &cc)?;

    let acc = dir.account(&config.lets_encrypt_email)?;
    let ord_new = spec.to_acme_order(&acc)?;
    let authorizations = ord_new.authorizations()?;

    for a in &authorizations {
        // LE may require validation for only a subset of requested domains
        if a.need_challenge() {
            let challenge = a.dns_challenge();
            let domain = DnsName::try_from(&String::from(a.domain_name()))?;
            dns::add(config, &domain, &challenge.dns_proof())?;
        }
    }

    let auth_dns_servers = spec.get_auth_dns_servers(config)?;
    let mut val_dns_servers = HashSet::new();
    for s in &config.val_dns_servers {
        val_dns_servers.insert(s.to_owned());
    }


    Ok(IssueOrder{
        spec: spec.clone(),
        authorizations,
        inner: ord_new,
        challenge_time: Utc::now(),
        auth_dns_servers,
        val_dns_servers,
    })
}

struct IssueOrder {
    spec: CertSpec,
    inner: NewOrder<MemoryPersist>,
    authorizations: Vec<Auth<MemoryPersist>>,
    challenge_time: chrono::DateTime<Utc>,
    auth_dns_servers: HashSet<String>,
    val_dns_servers: HashSet<String>,
}

impl IssueOrder {
    async fn issue(&self) -> Result<(), IssuerError> {
        log::data("Issuing", &self.spec);

        let pkey_pri = create_rsa_key(2048);
        let ord_csr = match self.inner.confirm_validations() {
            Some(csr) => Ok(csr),
            None => Err(IssuerError::ChallengeRejected)
        }?;

        let ord_cert =
            ord_csr.finalize_pkey(pkey_pri, 5000)?;
        let cert = ord_cert.download_and_save_cert()?;

        Ok(self.spec.persist(cert).await?)
    }
}

#[derive(Debug)]
pub enum IssuerError {
    ConfigurationError,
    ChallengeRejected,
    #[allow(dead_code)] // Debug only
    AcmeClient (acme_lib::Error),
    Dns (dns::DnsError),
    PersistError
}

impl std::convert::From<dns::DnsError> for IssuerError {
    fn from(error: dns::DnsError) -> IssuerError {
        IssuerError::Dns(error)
    }
}

impl std::convert::From<PersistError> for IssuerError {
    fn from(_: PersistError) -> IssuerError {
        IssuerError::PersistError
    }
}

impl std::convert::From<acme_lib::Error> for IssuerError {
    fn from(error: acme_lib::Error) -> IssuerError {
        IssuerError::AcmeClient(error)
    }
}

impl std::convert::From<common::SpecError> for IssuerError {
    fn from(_: common::SpecError) -> IssuerError {
        IssuerError::ConfigurationError
    }
}

#[derive(Debug)]
enum ResolverError<'l> {
    SystemResolveConf,
    #[allow(dead_code)] // Debug only
    NoIpsForResolversFound(&'l String),
    Other
}

impl std::convert::From<std::io::Error> for ResolverError<'_> {
    fn from(_: std::io::Error) -> Self {
        ResolverError::Other
    }
}

lazy_static! {
    static ref RESOLVERS: RwLock<Resolvers> = RwLock::new(Resolvers{
        inner: HashMap::with_capacity(0)
    });
}

struct Resolvers {
    inner: HashMap<String, TokioAsyncResolver>
}

impl Resolvers {
    fn get(&self, server: &String) -> Option<&TokioAsyncResolver> {
        self.inner.get(server)
    }
}

async fn init_resolvers(config: &FaytheConfig) -> Result<HashMap<String, TokioAsyncResolver>, ResolverError> {
    let mut resolvers = HashMap::new();

    for z in &config.zones {
        let server = &z.1.auth_dns_server;
        resolvers.insert(server.clone(), create_resolvers(server).await?);
    }
    for s in &config.val_dns_servers {
        resolvers.insert(s.to_string(), create_resolvers(s).await?);
    }
    Ok(resolvers)
}

async fn create_resolvers(server: &String) -> Result<TokioAsyncResolver, ResolverError> {

    let system_resolver = AsyncResolver::tokio_from_system_conf().or(Err(ResolverError::SystemResolveConf))?;

    //try-parse what's in the config file as an ip-address, if that fails, assume it's a hostname that can be looked up
    let ip: IpAddr = match server.parse() {
        Ok(ip) => Ok(ip),
        Err(_) => {
            match system_resolver.lookup_ip(server).await {
                Ok(res) => res.iter().next().ok_or(ResolverError::NoIpsForResolversFound(server)), // grabbing the first A record only for now
                Err(err) => {
                    Err(match err.kind() {
                        ResolveErrorKind::NoRecordsFound { .. } => ResolverError::NoIpsForResolversFound(server),
                        _ => ResolverError::Other
                    })
                }
            }
        }
    }?;

    let mut conf = ResolverConfig::new();
    for c in &*NameServerConfigGroup::from_ips_clear(&[ip.to_owned()], 53, true) {
        conf.add_name_server(c.to_owned());
    }
    let mut opts = ResolverOpts::default();
    // Never believe NXDOMAIN for more than 1 minute
    opts.negative_max_ttl = Some(Duration::new(60,0));
    Ok(AsyncResolver::tokio(conf, opts))
}
