use crate::dns::DNSError;

use super::ChallengeDriver;
use crate::config::WebhookDriver;

use std::collections::HashMap;

impl ChallengeDriver for WebhookDriver {
  fn add(&self, challenge_host: &String, proof: &String) -> Result<(), DNSError> {
    self.exec_add(Payload {
      records: vec![(challenge_host.clone(), Record {
        record_type: RecordType::TXT,
        content: Some(proof.clone()),
      })].into_iter().collect()
    })
  }

  fn delete(&self, challenge_host: &String) -> Result<(), DNSError> {
    self.exec_delete(Payload {
      records: vec![(challenge_host.clone(), Record {
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
  TXT,
}

static APP_USER_AGENT: &str = concat!(
  env!("CARGO_PKG_NAME"),
  "/",
  env!("CARGO_PKG_VERSION"),
);

impl WebhookDriver {
  
  fn get_client(&self) -> Result<reqwest::blocking::Client, reqwest::Error> {
    let client = reqwest::blocking::Client::builder();
    let client = client.timeout(std::time::Duration::from_secs(self.timeout_secs as u64));
    let client = client.user_agent(APP_USER_AGENT);
    client.build()
  }
  
  fn exec_add(&self, body: Payload) -> Result<(), DNSError> {
    self.get_client()?
      .put(self.url.clone())
      .json(&body)
      .send()
      .and(Ok(()))
      .map_err(std::convert::Into::into)
  }

  fn exec_delete(&self, body: Payload) -> Result<(), DNSError> {
    self.get_client()?
      .delete(self.url.clone())
      .json(&body)
      .send()
      .and(Ok(()))
      .map_err(std::convert::Into::into)
  }
}
