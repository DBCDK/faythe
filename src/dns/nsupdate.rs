use std::process::{Command, Stdio};
use crate::exec::{SpawnOk, OpenStdin, Wait};
use crate::dns::DNSError;

use super::ChallengeDriver;
use crate::config::NSUpdateDriver;

impl ChallengeDriver for NSUpdateDriver {
    fn add(&self, challenge_host: &String, proof: &String) -> Result<(), DNSError> {
        let command = self.add_cmd(&challenge_host, &proof);
        self.update_dns(&command)
    }

    fn delete(&self, challenge_host: &String) -> Result<(), DNSError> {
        let command = self.delete_cmd(&challenge_host);
        self.update_dns(&command)
    }
}

impl NSUpdateDriver {
    fn update_dns(&self, command: &String) -> Result<(), DNSError> {
        let mut cmd = Command::new("nsupdate");
        let mut child = cmd.arg("-k")
            .arg(&self.key)
            .stdin(Stdio::piped())
            .spawn_ok()?;
        {
            child.stdin_write(command)?;
        }
        
        Ok(child.wait()?)
    }

    fn add_cmd(&self, name: &String, proof: &String) -> String {
        format!("server {server}\n\
            update add {host} 120 TXT \"{proof}\"\n\
            send\n",
            server=&self.server,
            host=&name,
            proof=&proof)
    }
      
    fn delete_cmd(&self, name: &String) -> String {
        format!("server {server}\n\
            update delete {host} TXT\n\
            send\n",
            server=&self.server,
            host=&name)
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::common::PersistSpec::DONTPERSIST;
    use std::convert::TryFrom;
    use std::collections::HashSet;
    use crate::common::tests::*;
    use crate::common::{CertSpec, DNSName};
    use crate::dns::challenge_host;

    fn create_cert_spec(cn: &String) -> CertSpec {
        let dns_name = DNSName::try_from(cn).unwrap();
        CertSpec{
            name: String::from("test"),
            cn: dns_name,
            sans: HashSet::new(),
            persist_spec: DONTPERSIST,
        }
    }

    #[test]
    fn test_add_normal() {
        let config = create_test_file_config(false);
        let spec = create_cert_spec(&String::from("moo.unit.test"));
        let proof = String::from("abcdef1234");
        let zone = config.faythe_config.zones.get("unit.test").unwrap();
        let driver = NSUpdateDriver {
            server: String::from("ns.unit.test"),
            key: String::from("key")
        };

        let host = challenge_host(&spec.cn, Some(&zone));
        assert_eq!(driver.add_cmd(&host, &proof),
                   "server ns.unit.test\nupdate add _acme-challenge.moo.unit.test. 120 TXT \"abcdef1234\"\nsend\n")
    }

    #[test]
    fn test_add_wildcard() {
        let config = create_test_file_config(false);
        let spec = create_cert_spec(&String::from("*.unit.test"));
        let proof = String::from("abcdef1234");
        let zone = config.faythe_config.zones.get("unit.test").unwrap();
        let driver = NSUpdateDriver {
            server: String::from("ns.unit.test"),
            key: String::from("key")
        };

        let host = challenge_host(&spec.cn, Some(&zone));
        assert_eq!(driver.add_cmd(&host, &proof),
                   "server ns.unit.test\nupdate add _acme-challenge.unit.test. 120 TXT \"abcdef1234\"\nsend\n")
    }

    #[test]
    fn test_delete_normal() {
        let config = create_test_file_config(false);
        let spec = create_cert_spec(&String::from("moo.unit.test"));
        let zone = config.faythe_config.zones.get("unit.test").unwrap();
        let driver = NSUpdateDriver {
            server: String::from("ns.unit.test"),
            key: String::from("key")
        };

        let host = challenge_host(&spec.cn, Some(&zone));
        assert_eq!(driver.delete_cmd(&host),
                   "server ns.unit.test\nupdate delete _acme-challenge.moo.unit.test. TXT\nsend\n")
    }

    #[test]
    fn test_delete_wildcard() {
        let config = create_test_file_config(false);
        let spec = create_cert_spec(&String::from("*.unit.test"));
        let zone = config.faythe_config.zones.get("unit.test").unwrap();
        let driver = NSUpdateDriver {
            server: String::from("ns.unit.test"),
            key: String::from("key")
        };

        let host = challenge_host(&spec.cn, Some(&zone));
        assert_eq!(driver.delete_cmd(&host),
                   "server ns.unit.test\nupdate delete _acme-challenge.unit.test. TXT\nsend\n")
    }

    #[test]
    fn test_challenge_suffix() {
        let config = create_test_file_config(false);
        let spec = create_cert_spec(&String::from("*.suffixed.unit.test"));
        let proof = String::from("abcdef1234");
        let zone = config.faythe_config.zones.get("suffixed.unit.test").unwrap();
        let driver = NSUpdateDriver {
            server: String::from("ns.suffixed.unit.test"),
            key: String::from("key")
        };

        let host = challenge_host(&spec.cn, Some(&zone));
        assert_eq!(driver.add_cmd(&host, &proof),
                   "server ns.suffixed.unit.test\nupdate add _acme-challenge.suffixed.unit.test.acme.example.com. 120 TXT \"abcdef1234\"\nsend\n");

        assert_eq!(driver.delete_cmd(&host),
                   "server ns.suffixed.unit.test\nupdate delete _acme-challenge.suffixed.unit.test.acme.example.com. TXT\nsend\n")
    }
}
