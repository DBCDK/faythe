pub type VaultClient = vaultrs::client::VaultClient;

use crate::common::{Cert, ValidityVerifier};
use crate::common::{
    CertSpec, CertSpecable, IssueSource, PersistError, PersistSpec, SpecError, TouchError,
};
use crate::config::{VaultMonitorConfig, VaultPersistSpec};
use crate::log;
use crate::ConfigContainer;
use crate::FaytheConfig;
use acme_lib::Certificate;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use url::Url;
use vaultrs::client::VaultClientSettingsBuilder;
use vaultrs::error::ClientError;
use vaultrs::kv2;
use vaultrs_login::engines::approle::AppRoleLogin;
use vaultrs_login::LoginClient;

#[derive(Debug, Deserialize, Serialize)]
struct VaultAppRoleSecretID {
    secret_id: String,
    secret_id_accessor: String,
    secret_id_ttl: u64,
}

type CertName = String;

// Vault spec is parsed alongside the config, and combining fields
// corresponds to a path in vault.
// /<kv_mount>/<secret_prefix>/<key_infix>/<*_suffix>

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct VaultSpec {
    pub name: String,
    pub cn: String,
    #[serde(default)]
    pub sans: HashSet<String>,
    #[serde(default)]
    pub key_infix: Option<String>,
    #[serde(default = "default_cert_suffix")]
    pub cert_suffix: String,
    #[serde(default = "default_private_key_suffix")]
    pub private_key_suffix: String,
}

fn default_cert_suffix() -> String {
    "cert".to_string()
}

fn default_private_key_suffix() -> String {
    "private".to_string()
}

#[derive(Debug)]
pub enum VaultError {
    Client(ClientError),
    IO(std::io::Error),
    LockPoison,
    SpecError(crate::common::SpecError),
    TimeStampParseError(chrono::ParseError),
    UTF8(std::str::Utf8Error),
    RecentlyTouched,
}

impl std::convert::From<std::str::Utf8Error> for VaultError {
    fn from(inner: std::str::Utf8Error) -> Self {
        VaultError::UTF8(inner)
    }
}

impl std::convert::From<std::io::Error> for VaultError {
    fn from(inner: std::io::Error) -> Self {
        VaultError::IO(inner)
    }
}

impl std::convert::From<crate::common::SpecError> for VaultError {
    fn from(inner: crate::common::SpecError) -> Self {
        VaultError::SpecError(inner)
    }
}

impl std::convert::From<chrono::ParseError> for VaultError {
    fn from(inner: chrono::ParseError) -> Self {
        VaultError::TimeStampParseError(inner)
    }
}
impl std::convert::From<VaultError> for PersistError {
    fn from(inner: VaultError) -> Self {
        PersistError::Vault(inner)
    }
}
impl std::convert::From<ClientError> for VaultError {
    fn from(inner: ClientError) -> Self {
        VaultError::Client(inner)
    }
}

// Returns a hashmap that associates a certificate with it's path name in vault
pub fn list(config: &VaultMonitorConfig) -> Result<HashMap<CertName, VaultCert>, VaultError> {
    let rt = tokio::runtime::Runtime::new()?;
    let certs: Result<HashMap<CertName, VaultCert>, VaultError> = rt.block_on(async {
        let client = authenticate(
            &config.role_id_path,
            &config.secret_id_path,
            &config.vault_addr,
        )
        .await?;

        let mut certs: HashMap<CertName, VaultCert> = HashMap::new();
        for s in &config.specs {
            let vault_paths = default_key_names(&config, s);
            let cert_raw: Result<VaultData, _> =
                kv2::read(&*client, &config.kv_mount, &vault_paths.cert).await;

            match cert_raw {
                Ok(raw) => match Cert::parse(&raw.value.as_bytes().to_vec()) {
                    Ok(cert) => {
                        certs.insert(s.name.to_string(), VaultCert { cert });
                    }
                    Err(err) => log::error(
                        &format!(
                            "LIST: failed parse raw cert data for path: {}",
                            &vault_paths.cert
                        ),
                        &err,
                    ),
                },
                // If faythe does not find a certificate, a new one will be issued.
                // So don't propagate this 404.
                Err(_err @ ClientError::APIError { code: 404, .. }) => {}
                Err(err) => log::error(
                    &format!(
                        "LIST: failed to vault-kv-get raw cert data for path: {}",
                        &vault_paths.cert
                    ),
                    &err,
                ),
            }
        }
        Ok(certs)
    });

    Ok(certs?)
}

fn read_to_string(path: &Path) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path).map_err(|e| {
        log::error(&format!("failed to read file: {:?}", &path), &e);
        e
    })
}

lazy_static! {
    static ref CLIENT: Mutex<Option<Arc<VaultClient>>> = Mutex::new(None);
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultKVSettings {
    kv_mount: String,
    key_prefix: String,
}

impl std::convert::From<&VaultMonitorConfig> for VaultKVSettings {
    fn from(inner: &VaultMonitorConfig) -> Self {
        VaultKVSettings {
            kv_mount: inner.kv_mount.clone(),
            key_prefix: inner.key_prefix.clone(),
        }
    }
}

impl std::convert::From<&KeyNames> for VaultKVSettings {
    fn from(inner: &KeyNames) -> Self {
        inner.kv_settings.clone()
    }
}

#[inline(always)]
async fn renew_client(client: &VaultClient) -> Result<(), ClientError> {
    let token_resp = vaultrs::client::Client::lookup(client).await?;
    if token_resp.ttl < (token_resp.creation_ttl / 2) {
        // empty string means increment token endpoint by default ttl value
        let _auth_info = vaultrs::client::Client::renew(client, Some("")).await?;
        log::info("Client endpoint extended. Lease duration extended by default token ttl value.");
    }
    Ok(())
}

// Only login to vault if current client is unhealthy
pub async fn authenticate(
    role_id_path: &Path,
    secret_id_path: &Path,
    vault_addr: &Url,
) -> Result<Arc<VaultClient>, VaultError> {
    let mut existing_client = CLIENT.lock().map_err(|_| VaultError::LockPoison)?;
    let client_health = match &*existing_client {
        Some(client) => {
            // Derefence and take lock from client
            let client = &**client;
            let renewed_client = renew_client(client).await;

            match renewed_client {
                Ok(_) => true,
                Err(ClientError::APIError { code: 404, .. }) => true,
                _ => false,
            }
        }
        _ => false,
    };

    Ok(if client_health {
        (*existing_client).as_ref().unwrap().clone()
    } else {
        log::info("vault client unhealthy or uninitialized, trying to authenticate...");
        let new_client = Arc::new(login(role_id_path, secret_id_path, vault_addr).await?);
        *existing_client = Some(new_client.clone());
        new_client
    })
}

/// A login method which uses AppRole credentials for obtaining a new token.
pub async fn login(
    role_id_path: &Path,
    secret_id_path: &Path,
    vault_addr: &Url,
) -> Result<VaultClient, VaultError> {
    let role_id = read_to_string(&role_id_path)?;
    let secret_id = read_to_string(&secret_id_path)?;
    let role_id = role_id.trim();
    let secret_id = secret_id.trim();

    let mut client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(vault_addr.as_str())
            .timeout(Some(std::time::Duration::from_secs(10)))
            .build()
            .unwrap(),
    )?;

    let applogin = AppRoleLogin {
        role_id: role_id.to_string(),
        secret_id: secret_id.to_string(),
    };

    client.login("approle", &applogin).await?;
    Ok(client)
}

#[derive(Debug, Deserialize, Serialize)]
struct Secret {
    value: String,
}
// This trait implementation used by the issuer to persist certificates
pub fn persist(persist_spec: &VaultPersistSpec, cert: Certificate) -> Result<(), PersistError> {
    let rt = tokio::runtime::Runtime::new()?;
    let vault_write: Result<(), VaultError> = rt.block_on(async {
        let client = authenticate(
            &persist_spec.role_id_path,
            &persist_spec.secret_id_path,
            &persist_spec.vault_addr,
        )
        .await?;

        kv2::set(
            &*client,
            &persist_spec.kv_mount,
            &persist_spec.paths.cert,
            &kv_data(std::str::from_utf8(&cert.certificate().as_bytes())?.to_string()),
        )
        .await?;

        kv2::set(
            &*client,
            &persist_spec.kv_mount,
            &persist_spec.paths.key,
            &kv_data(std::str::from_utf8(&cert.private_key().as_bytes())?.to_string()),
        )
        .await?;
        Ok(())
    });
    Ok(vault_write?)
}

impl IssueSource for VaultSpec {
    fn get_raw_cn(&self) -> String {
        self.cn.clone()
    }
    fn get_raw_sans(&self) -> HashSet<String> {
        self.sans.clone()
    }
}

impl VaultMonitorConfig {
    pub fn to_persist_spec(&self, cert_spec: &VaultSpec) -> VaultPersistSpec {
        let names = default_key_names(&self, &cert_spec);

        VaultPersistSpec {
            role_id_path: self.role_id_path.clone(),
            secret_id_path: self.secret_id_path.clone(),
            vault_addr: self.vault_addr.clone(),
            kv_mount: self.kv_mount.clone(),
            paths: names,
        }
    }
}

// Convenience method creates complete vault path
// to the cert, the key and meta (faythe) file.
fn default_key_names(config: &VaultMonitorConfig, spec: &VaultSpec) -> KeyNames {
    let cert = [
        config.key_prefix.as_str(),
        spec.key_infix.as_ref().unwrap_or(&spec.name).as_str(),
        spec.cert_suffix.as_str(),
    ]
    .join("/");
    let key = [
        config.key_prefix.as_str(),
        spec.key_infix.as_ref().unwrap_or(&spec.name).as_str(),
        spec.private_key_suffix.as_str(),
    ]
    .join("/");
    let meta = [
        config.key_prefix.as_str(),
        spec.key_infix.as_ref().unwrap_or(&spec.name).as_str(),
        "faythe".to_string().as_str(),
    ]
    .join("/");

    KeyNames {
        kv_settings: config.into(),
        cert,
        key,
        meta,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyNames {
    pub kv_settings: VaultKVSettings,
    pub cert: String,
    pub key: String,
    pub meta: String,
}

fn kv_data(value: String) -> HashMap<String, String> {
    let mut data: HashMap<String, String> = HashMap::with_capacity(1);
    data.insert("value".to_string(), value);
    data
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultData {
    value: String,
}

impl VaultData {
    fn borrow(&self) -> &str {
        &self.value
    }
}

impl CertSpecable for VaultSpec {
    fn to_cert_spec(&self, config: &ConfigContainer) -> Result<CertSpec, SpecError> {
        let cn = self.get_computed_cn(&config.faythe_config)?;
        let monitor_config = config.get_vault_monitor_config()?;
        Ok(CertSpec {
            name: self.name.clone(),
            cn,
            sans: self.get_computed_sans(&config.faythe_config)?,
            persist_spec: PersistSpec::VAULT(monitor_config.to_persist_spec(&self)),
        })
    }
    // Write meta file, meta file just contains a rfc3339 timestamp
    fn touch(&self, config: &ConfigContainer) -> Result<(), TouchError> {
        let monitor_config = config.get_vault_monitor_config()?;
        let persist_spec = monitor_config.to_persist_spec(&self);
        let rt = tokio::runtime::Runtime::new()?;
        let write_meta_file: Result<(), VaultError> = rt.block_on(async {
            let client = authenticate(
                &persist_spec.role_id_path,
                &persist_spec.secret_id_path,
                &persist_spec.vault_addr,
            )
            .await?;

            kv2::set(
                &*client,
                &persist_spec.kv_mount,
                &persist_spec.paths.meta,
                &kv_data(chrono::Utc::now().to_rfc3339()),
            )
            .await?;

            Ok(())
        });
        write_meta_file.map_err(|e| {
            log::error("failed to write meta file", &e);
            TouchError::Failed
        })
    }
    // Check if meta file is too old, and a new certicate
    // must be issued.
    fn should_retry(&self, config: &ConfigContainer) -> bool {
        match || -> Result<(), VaultError> {
            let monitor_config = config.get_vault_monitor_config()?;
            let persist_spec = monitor_config.to_persist_spec(&self);
            let rt = tokio::runtime::Runtime::new()?;

            let write_meta_file: Result<(), VaultError> = rt.block_on(async {
                let client = authenticate(
                    &persist_spec.role_id_path,
                    &persist_spec.secret_id_path,
                    &persist_spec.vault_addr,
                )
                .await?;

                let raw_read: Result<VaultData, ClientError> =
                    kv2::read(&*client, &persist_spec.kv_mount, &persist_spec.paths.meta).await;

                match raw_read {
                    Ok(value) => {
                        let time_stamp = chrono::DateTime::parse_from_rfc3339(&value.borrow())?;
                        let diff = chrono::Utc::now().signed_duration_since(time_stamp);
                        match diff
                            > chrono::Duration::milliseconds(
                                config.faythe_config.issue_grace as i64,
                            ) {
                            true => Ok(()),
                            false => Err(VaultError::RecentlyTouched),
                        }
                    }
                    Err(_err @ ClientError::APIError { code: 404, .. }) => Ok(()), // if the key doesn't exist, just create it
                    Err(err) => Err(err.into()), // unexpected Vault-error
                }
            });
            Ok(write_meta_file?)
        }() {
            Ok(()) => true,
            Err(VaultError::RecentlyTouched) => false, // who cares, don't log this
            Err(err) => {
                log::error("failed to read faythe meta-entry from vault", &err);
                false
            }
        }
    }
}

#[derive(Debug)]
pub struct VaultCert {
    cert: Cert,
}

impl ValidityVerifier for VaultCert {
    fn is_valid(&self, config: &FaytheConfig, spec: &CertSpec) -> bool {
        self.cert.is_valid(config, spec)
    }
}
