use crate::dns::DnsError;

use super::ChallengeDriver;
use crate::config::WebhookDriver;

use reqwest::blocking::Client;
use std::collections::HashMap;
use std::convert::Into;
use std::time::Duration;

impl ChallengeDriver for WebhookDriver {
  fn add(&self, challenge_host: &str, proof: &str) -> Result<(), DnsError> {
    self.exec_add(Payload {
      records: vec![(challenge_host.to_owned(), Record {
        record_type: RecordType::TXT,
        content: Some(proof.to_owned()),
      })].into_iter().collect()
    })
  }

  fn delete(&self, challenge_host: &str) -> Result<(), DnsError> {
    self.exec_delete(Payload {
      records: vec![(challenge_host.to_owned(), Record {
        record_type: RecordType::TXT,
        content: None,
      })].into_iter().collect()
    })
  }
}

#[derive(Debug, Serialize)]
struct Payload {
  records: HashMap<String, Record>,
}

#[derive(Debug, Serialize)]
struct Record {
  #[serde(rename = "type")]
  record_type: RecordType,
  content: Option<String>,
}

#[derive(Debug, Serialize)]
enum RecordType {
  #[allow(clippy::upper_case_acronyms)]
  TXT,
}

static APP_USER_AGENT: &str = concat!(
  env!("CARGO_PKG_NAME"),
  "/",
  env!("CARGO_PKG_VERSION"),
);

impl WebhookDriver {
  fn get_client(&self) -> Result<Client, reqwest::Error> {
    let client = Client::builder();
    let client = client.timeout(Duration::from_secs(self.timeout_secs as u64));
    let client = client.user_agent(APP_USER_AGENT);
    client.build()
  }
  
  fn exec_add(&self, body: Payload) -> Result<(), DnsError> {
    self.get_client()?
      .put(self.url.clone())
      .json(&body)
      .send()
      .and(Ok(()))
      .map_err(Into::into)
  }

  fn exec_delete(&self, body: Payload) -> Result<(), DnsError> {
    self.get_client()?
      .delete(self.url.clone())
      .json(&body)
      .send()
      .and(Ok(()))
      .map_err(Into::into)
  }
}
