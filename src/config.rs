use crate::common::SpecError;
use crate::file::FileSpec;
use crate::vault::{KeyNames, VaultSpec};
use serde::Deserializer;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::prelude::v1::Vec;
use url::Url;
use serde::Serializer;

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FaytheConfig {
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    pub lets_encrypt_url: String,
    pub lets_encrypt_proxy: Option<String>,
    pub lets_encrypt_email: String,
    pub zones: HashMap<String, Zone>,
    pub val_dns_servers: Vec<String>,
    #[serde(default = "default_interval")]
    pub monitor_interval: u64,
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold: u16,
    #[serde(default = "default_issue_grace")]
    pub issue_grace: u64,
    #[serde(default)]
    pub kube_monitor_configs: Vec<KubeMonitorConfig>,
    #[serde(default)]
    pub file_monitor_configs: Vec<FileMonitorConfig>,
    #[serde(default)]
    pub vault_monitor_configs: Vec<VaultMonitorConfig>,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct KubeMonitorConfig {
    pub secret_namespace: String,
    pub secret_hostlabel: String,
    #[serde(default = "default_wildcard_cert_k8s_prefix")]
    pub wildcard_cert_prefix: String,
    #[serde(default = "default_k8s_touch_annotation")]
    pub touch_annotation: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct VaultMonitorConfig {
    pub role_id_path: PathBuf,
    pub secret_id_path: PathBuf,
    pub specs: Vec<VaultSpec>,
    #[serde(deserialize_with = "deserialize_url", serialize_with = "serialize_url")]
    pub vault_addr: Url,
    #[serde(default = "default_kv_mount")]
    pub kv_mount: String,
    pub key_prefix: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct VaultPersistSpec {
    pub role_id_path: PathBuf,
    pub secret_id_path: PathBuf,
    #[serde(deserialize_with = "deserialize_url", serialize_with = "serialize_url")]
    pub vault_addr: Url,
    pub kv_mount: String,
    pub paths: KeyNames,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileMonitorConfig {
    pub directory: String,
    pub specs: Vec<FileSpec>,
    pub prune: bool
}

pub enum MonitorConfig {
    Kube(KubeMonitorConfig),
    File(FileMonitorConfig),
    Vault(VaultMonitorConfig),
}

pub struct ConfigContainer {
    pub faythe_config: FaytheConfig,
    pub monitor_config: MonitorConfig
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub server: String,
    pub key: String,
    pub challenge_suffix: Option<String>,
    #[serde(default = "default_issue_wildcard_certs")]
    pub issue_wildcard_certs: bool,
}

impl ConfigContainer {
    pub fn get_kube_monitor_config(&self) -> Result<&KubeMonitorConfig, SpecError> {
        Ok(match &self.monitor_config {
            MonitorConfig::Kube(c) => Ok(c),
            _ => Err(SpecError::InvalidConfig)
        }?)
    }
    pub fn get_file_monitor_config(&self) -> Result<&FileMonitorConfig, SpecError> {
        Ok(match &self.monitor_config {
            MonitorConfig::File(c) => Ok(c),
            _ => Err(SpecError::InvalidConfig),
        }?)
    }
    pub fn get_vault_monitor_config(&self) -> Result<&VaultMonitorConfig, SpecError> {
        Ok(match &self.monitor_config {
            MonitorConfig::Vault(c) => Ok(c),
            _ => Err(SpecError::InvalidConfig),
        }?)
    }
}

// millis (5 seconds)
fn default_interval() -> u64 {
    5 * 1000
}

// millis (8 hours)
fn default_issue_grace() -> u64 {
    60 * 60 * 8 * 1000
}

// days
fn default_renewal_threshold() -> u16 { 30 }

fn default_issue_wildcard_certs() -> bool { false }

fn default_wildcard_cert_k8s_prefix() -> String { "wild--card".to_string() }

fn default_k8s_touch_annotation() -> Option<String> { Some("faythe.touched".to_string()) }

fn default_metrics_port() -> u16 {
    9105
}
fn default_kv_mount() -> String {
    "kv".to_string()
}

fn deserialize_url<'de, D>(data: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = serde::de::Deserialize::deserialize(data)?;
    Url::parse(s).map_err(serde::de::Error::custom)
}

fn serialize_url<S>(url: &Url, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(url.as_str())
}

pub fn parse_config_file(file: &str) -> serde_json::Result<FaytheConfig> {
    let path = std::path::Path::new(&file);
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let c: serde_json::Result<FaytheConfig> = serde_json::from_str(&data);
    c
}
