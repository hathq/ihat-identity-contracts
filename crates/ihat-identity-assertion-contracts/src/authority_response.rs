use serde::{Deserialize, Serialize};

use crate::AuthorityResult;

pub const AUTHORITY_RESPONSE_SCHEMA: &str = "ihat://identity/authority-host/response/v1";
pub const AUTHORITY_RESPONSE_MAX_TTL_SECONDS: u64 = 30;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityRejectionCode {
    ConfigurationRejected,
    RequestInvalid,
    EvidenceRejected,
    IdentityRuntimeRejected,
    LocalIoFailed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum ResponseOutcome {
    Committed { result: AuthorityResult },
    Rejected { code: AuthorityRejectionCode },
    Unknown { reconcile_digest: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityResponseV1 {
    pub schema: String,
    pub request_id: String,
    pub command_type: String,
    pub command_digest: String,
    pub config_generation: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub outcome: ResponseOutcome,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityResponseBinding<'a> {
    pub request_id: &'a str,
    pub command_type: &'a str,
    pub command_digest: &'a str,
    pub minimum_config_generation: u64,
}
