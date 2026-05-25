use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OobConfig {
    pub provider: OobProvider,
    pub poll_interval_secs: u64,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OobProvider {
    Interactsh { server: String },
    BurpCollaborator { url: String },
    CustomDns { pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OobCanary {
    pub id: Uuid,
    pub expected_dns: String,
    pub expected_http_path: String,
    #[serde(skip)]
    pub created_at: Option<Instant>,
}

// `#[non_exhaustive]` future-proofs the enum: downstream pattern matches
// MUST include a `_ =>` arm, so adding a new interaction protocol later
// (HTTP/3, DoH, STUN, etc.) is no longer a breaking change.
//
// SMTP / LDAP / FTP were silently dropped at interactsh_provider.rs's
// `_ =&gt; continue` arm before — meaning Oracle UTL_SMTP-based blind
// SQLi, every LDAP injection, every ftp:// SSRF callback reported
// `OobConfirmation::Timeout` despite the payload actually working.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum OobInteraction {
    DnsQuery {
        query: String,
        source_ip: String,
    },
    HttpRequest {
        path: String,
        headers: Vec<(String, String)>,
        body: Option<String>,
    },
    SmtpMessage {
        // Full interactsh `raw_request` of the SMTP exchange — HELO,
        // MAIL FROM, RCPT TO, DATA. Single string because the wire
        // format is line-delimited and consumers usually grep it.
        raw: String,
        source_ip: String,
    },
    LdapQuery {
        // Distinguished name extracted from the LDAP bind/search the
        // payload caused. Useful for confirming that an LDAP-injection
        // payload reached the directory server.
        dn: String,
        source_ip: String,
    },
    FtpCommand {
        // The FTP command line (USER / PASS / RETR / STOR) that the
        // payload caused the target to issue.
        command: String,
        source_ip: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OobConfirmation {
    Confirmed,
    Timeout,
    Error,
}
