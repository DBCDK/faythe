# Faythe

Tool for monitoring, issuing and persisting x509 certificates, using Let's Encrypt.

## Configuration

Faythe requires a path to a json configuration file passed as first cmdline arg.
A sample configuration file can be found at `/config.json` in this repo.

Available config options:

**lets_encrypt_url** Which URL to use for Let's Encrypt communication. See for example: https://letsencrypt.org/docs/staging-environment/

**lets_encrypt_email** Faythe uses anonymous accounts with Let's Encrypt (meaning no auth is performed),
but some e-mail address identifying the client is still required.

**auth_dns_server** The address of the DNS-server to use for DDNS update requests.

**auth_dns_zone** The DNS-zone to use for DDNS update requests.

**auth_dns_key** Path to an nsupdate compatible private key to use for authing DDNS-requests at `auth_dns_server`.

**val_dns_servers** List of external DNS-servers to use for validating that new DNS-records have propagated correctly.
Should preferably be set to a server which is further away (net topology-wise) than `auth_dns_server`.

**monitor_interval** The interval (in milliseconds) between checks of data
default: 5000 (5 seconds).

**renewal_threshold** The time (in days) before expiry of a certificate, which Faythe must start attempts to renew the cert.
default: 30

**issue_grace** The grace period (in milliseconds) that must pass between each attempt to issue a certificate for the same domain. In order
not to spam Let's Encrypt with repeated requests. See: https://letsencrypt.org/docs/rate-limits/
default: 28800000 (8 hours)

**issue_wildcard_certs** Whether to issue wildcard certificates. (true/false)
default: false

## Design

As of writing, Faythe workload is divided into two chunks, Monitoring and Issuing.

### Monitoring
Monitoring is the process of comparing requested certs to existing certs.

If issuance needs to happen, eg. due to expiry, a request for issuing is send to the Issuer-thread.

### Issuing
The actual issuing of certificates involves three high level steps:

1. Ask Let's encrypt for authentication on domain ownership
2. Let's encrypt issues a challenge which must be published to the internet for LE to validate
3. When LE approves the challenge response, the cert is issued and stored.

RE 2) Let's encrypt returns a challenge string which Faythe inserts via nsupdate as a TXT-record into "auth_dns_zone".
The record takes the form of `_acme-challenge.<host> IN 120 TXT <challenge>`. Before inserting the record into the DNS-zone
Faythe will try to delete any existing TXT-records matching the hostname.

RE 3) Before asking Let's encrypt to check the TXT-record, Faythe will itself query first "auth_dns_server" and then
"val_dns_server" and confirm that the expected record is visible both places. Let's Encrypt don't like validation errors,
which is encompassed by its own special rate limit. Thus, it is desirable to double check challenge propagation locally.  

## Deployment

`nix develop`, and then standard `cargo build` and `cargo run <config-file>` can be used.

Runtime dependencies are currently:

- dig (provided by "dnsutils" on Nix)
- nsupdate (provided by "dnsutils" on Nix)

The flake shell environment will provide these as inputs.
