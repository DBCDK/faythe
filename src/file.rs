extern crate walkdir;


use crate::config::{FileMonitorConfig, FaytheConfig, ConfigContainer};
use std::collections::{HashMap, HashSet};
use crate::common::{ValidityVerifier, CertSpecable, CertSpec, FileMode, FilePermissions, SpecError, PersistSpec, TouchError, IssueSource, FilePersistSpec, Cert, PersistError, CertName};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use acme_lib::Certificate;
use std::io::Write;
use std::io::Read;
use std::time::SystemTime;
use std::os::unix::fs::PermissionsExt;
use crate::log;
use std::fs;
use std::fs::Permissions;
use self::walkdir::WalkDir;
use std::process::Command;
use std::process::Stdio;

pub fn read_certs(config: &FileMonitorConfig) -> Result<HashMap<CertName, FileCert>, FileError> {
    let mut certs = HashMap::new();
    let mut wanted_files = HashSet::new();
    for s in &config.specs {
        let names = default_file_names(s);
        names.insert_into(config, &mut wanted_files);
        let raw = read_file(absolute_file_path(config, &names, &names.cert).as_path()).unwrap_or_default();
        if let Ok(cert) = Cert::parse(&raw) {
            certs.insert(s.name.clone(), FileCert{cert});
        } else {
            log::data("dropping secret due to invalid cert", &names.cert);
        }
    }
    if config.prune {
        prune(config, &wanted_files);
    }
    Ok(certs)
}

fn prune(config: &FileMonitorConfig, wanted_files: &HashSet<PathBuf>) {
    let unwanted = WalkDir::new(&config.directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && !wanted_files.contains(e.path()));

    for f in unwanted {
        let path = f.path();
        match fs::remove_file(path) {
            Ok(_) => log::data("Pruned file", &path),
            Err(e) => log::error(&format!("failed to prune file: {}", &path.display()), &e)
        }
    }

    // unwanted files are removed ^ , now: remove empty directories

    let me = absolute_dir_path(config, Some(&config.directory));
    let dirs = WalkDir::new(&config.directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir() && e.path() != me && e.path().read_dir().is_ok());

    for d in dirs {
        let path = d.path();
        if path.read_dir().unwrap().next().is_none() {
            match fs::remove_dir(path) {
                Ok(_) => log::data("Removed directory", &path),
                Err(e) => log::error(&format!("failed to remove directory: {}", &path.display()), &e)
            }
        }
    }
}

fn default_file_names(spec: &FileSpec) -> FileNames {
    let sub_directory = match &spec.sub_directory {
        Some(n) => Some(n.clone()),
        None => Some(spec.name.to_string())
    };
    let cert = match &spec.cert_file_name {
        Some(n) => Some(n.clone()),
        None => Some(String::from("fullchain.pem"))
    }.unwrap();
    let key = match &spec.key_file_name {
        Some(n) => Some(n.clone()),
        None => Some(String::from("privkey.pem"))
    }.unwrap();
    let meta = format!("{name}.faythe",name=spec.name);

    FileNames {
        sub_directory, // will always be Some(sub_dir), currently sub directory persistent can't be disabled
        cert,
        key,
        meta
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, FileError> {
    let mut data: Vec<u8> = Vec::new();
    let mut file = File::open(path)?;
    file.read_to_end(&mut data)?;
    Ok(data)
}

#[derive(Clone, Debug)]
pub struct FileCert {
    pub cert: Cert
}

impl ValidityVerifier for FileCert {
    fn is_valid(&self, config: &FaytheConfig, spec: &CertSpec) -> bool {
        self.cert.is_valid(config, spec)
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct FileSpec {
    pub name: String,
    pub cn: String,
    #[serde(default)]
    pub sans: HashSet<String>,
    #[serde(default)]
    pub sub_directory: Option<String>,
    #[serde(default)]
    pub cert_file_name: Option<String>,
    #[serde(default)]
    pub key_file_name: Option<String>,
    #[serde(default)]
    pub cert_file_perms: Option<FilePermissions>,
    #[serde(default)]
    pub key_file_perms: Option<FilePermissions>,
}

impl IssueSource for FileSpec {
    fn get_raw_cn(&self) -> String {
        self.cn.clone()
    }
    fn get_raw_sans(&self) -> HashSet<String> {
        self.sans.clone()
    }
}

impl CertSpecable for FileSpec {
    fn to_cert_spec(&self, config: &ConfigContainer) -> Result<CertSpec, SpecError> {
        let cn = self.get_computed_cn(&config.faythe_config)?;
        let monitor_config = config.get_file_monitor_config()?;
        let names = default_file_names(self);
        Ok(CertSpec{
            name: self.name.clone(),
            cn,
            sans: self.get_computed_sans(&config.faythe_config)?,
            persist_spec: PersistSpec::File(FilePersistSpec{
                private_key_path: absolute_file_path(monitor_config, &names, &names.key),
                public_key_path: absolute_file_path(monitor_config, &names, &names.cert),
                cert_file_perms: self.cert_file_perms.clone(),
                key_file_perms: self.key_file_perms.clone(),
            }),
        })
    }

    async fn touch(&self, config: &ConfigContainer) -> Result<(), TouchError> {
        let monitor_config = config.get_file_monitor_config()?;
        let names = default_file_names(self);
        let sub_dir = absolute_dir_path(monitor_config, names.sub_directory.as_ref());
        if names.sub_directory.is_some() && !sub_dir.exists() {
            fs::create_dir(&sub_dir)?;
            sub_dir.metadata()?.permissions().set_mode(0o755) // rwxr-xr-x
        }
        let file_path = absolute_file_path(monitor_config, &names, &names.meta);
        let mut _file = OpenOptions::new().truncate(true).write(true).create(true).open(file_path)?;
        Ok(())
    }

    async fn should_retry(&self, config: &ConfigContainer) -> bool {
        use std::time::Duration;

        !matches!(|| -> Result<(), TouchError> {
            let monitor_config = config.get_file_monitor_config()?;
            let names = default_file_names(self);
            let file = File::open(absolute_file_path(monitor_config, &names, &names.meta))?;
            let metadata = file.metadata()?;
            let modified = metadata.modified()?;
            let diff: Duration = SystemTime::now().duration_since(modified)?;
            match diff > Duration::from_millis(config.faythe_config.issue_grace) {
                true => Ok(()),
                false => Err(TouchError::RecentlyTouched)
            }
        }(), Err(TouchError::RecentlyTouched))
    }
}

fn absolute_dir_path(config: &FileMonitorConfig, dir: Option<&String>) -> PathBuf {
    match dir {
        Some(dir) => Path::new(&config.directory).join(dir),
        None => Path::new(&config.directory).to_path_buf()
    }
}

fn absolute_file_path(config: &FileMonitorConfig, names: &FileNames, file: &String) -> PathBuf {
    absolute_dir_path(config, names.sub_directory.as_ref()).join(file)
}

#[derive(Clone, Debug)]
struct FileNames {
    sub_directory: Option<String>,
    cert: String,
    key: String,
    meta: String
}

impl FileNames {
    fn insert_into(&self, config: &FileMonitorConfig, set: &mut HashSet<PathBuf>) {
        set.insert(absolute_file_path(config, self, &self.cert));
        set.insert(absolute_file_path(config, self, &self.key));
        set.insert(absolute_file_path(config, self, &self.meta));
    }
}

#[derive(Debug)]
pub enum FileError {
    IO
}

pub fn persist(spec: &FilePersistSpec, cert: &Certificate) -> Result<(), PersistError> {
    let mut pub_file = File::create(&spec.public_key_path)?;
    let mut priv_file = File::create(&spec.private_key_path)?;
    let pub_buf = cert.certificate().as_bytes();
    let priv_buf = cert.private_key().as_bytes();

    // Ownership and permissions
    let pub_key_permissions = Permissions::from_mode(spec.cert_file_perms.as_ref().map_or(FileMode(0o644), |p| p.mode.as_ref().map(|m| m.clone()).unwrap_or(FileMode(0o644))).0); // default: rw-r--r--
    let priv_key_permissions = Permissions::from_mode(spec.key_file_perms.as_ref().map_or(FileMode(0o640), |p| p.mode.as_ref().map(|m| m.clone()).unwrap_or(FileMode(0o640))).0); // default: rw-r-----
    pub_file.set_permissions(pub_key_permissions)?;
    priv_file.set_permissions(priv_key_permissions)?;
    if let Some(perms) = &spec.cert_file_perms {
        if perms.user.is_some() || perms.group.is_some() {
            chown(perms.user.as_deref(), perms.group.as_deref(), &spec.public_key_path)?;
        }
    }
    if let Some(perms) = &spec.key_file_perms {
        if perms.user.is_some() || perms.group.is_some() {
            chown(perms.user.as_deref(), perms.group.as_deref(), &spec.private_key_path)?;
        }
    }

    // Flush contents to files
    pub_file.write_all(pub_buf)?;
    priv_file.write_all(priv_buf)?;
    Ok(())
}

fn chown(user: Option<&str>, group: Option<&str>, path: &Path) -> Result<(), PersistError> {
    let mut ownership_arg = user.unwrap_or("").to_string();
    if let Some(g) = group {
        ownership_arg.push(':');
        ownership_arg.push_str(g);
    }
    log::info(&format!("changing ownership to: {} for path: {}", &ownership_arg, &path.display()));

    let mut cmd = Command::new("chown");
    match cmd
        .arg(ownership_arg)
        .arg(path)
        .stderr(Stdio::piped())
        .output() {

        Ok(output) => {
            match output.status.success() {
                true => Ok(()),
                false => {
                    log::error("chown failed", &output.stderr);
                    Err(PersistError::File(FileError::IO))
                }
            }
        },
        Err(e) => { log::error("chown failed", &e); Err(PersistError::File(FileError::IO)) }
    }
}

impl std::convert::From<std::io::Error> for FileError {
    fn from(_: std::io::Error) -> Self {
        FileError::IO
    }
}

impl std::convert::From<std::io::Error> for PersistError {
    fn from(_: std::io::Error) -> Self {
        PersistError::File(FileError::IO)
    }
}

impl std::convert::From<std::io::Error> for TouchError {
    fn from(_: std::io::Error) -> Self {
        TouchError::Failed
    }
}

impl std::convert::From<std::time::SystemTimeError> for TouchError {
    fn from(_: std::time::SystemTimeError) -> Self {
        TouchError::Failed
    }
}
