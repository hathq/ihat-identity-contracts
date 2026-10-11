use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginFreshUvCommand {
    pub command_id: String,
    pub credential_id: String,
    pub identity_nonce: String,
    pub source_device_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub session_ref: String,
    pub operation_digest_sha256: String,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub device_epoch: u64,
    pub session_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinishFreshUvCommand {
    pub command_id: String,
    pub attempt_id: String,
    pub credential_id: String,
    pub client_data_json_base64url: String,
    pub authenticator_data_base64url: String,
    pub signature_der_base64url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileCommand {
    pub original_request_id: String,
    pub original_command_digest: String,
}
