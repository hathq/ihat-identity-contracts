use serde::{Deserialize, Serialize};

use crate::AuthorityWireError;

pub const CURRENT_IDENTITY_MAX_TTL_SECONDS: u64 = 30;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCurrentDeviceIdentityEvidenceCommand {
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub audience: String,
    pub identity_nonce: String,
    pub ttl_seconds: u64,
    pub session_sender_key_fingerprint: String,
    pub session_sender_proof_id: String,
}

pub(crate) fn validate(
    value: &IssueCurrentDeviceIdentityEvidenceCommand,
) -> Result<(), AuthorityWireError> {
    let identifiers = [
        &value.service_id,
        &value.pairwise_subject,
        &value.device_id,
        &value.audience,
        &value.identity_nonce,
        &value.session_sender_proof_id,
    ];
    if identifiers.iter().any(|value| !identifier(value))
        || value.identity_nonce == value.session_sender_proof_id
        || !(1..=CURRENT_IDENTITY_MAX_TTL_SECONDS).contains(&value.ttl_seconds)
        || !lower_hex_32(&value.session_sender_key_fingerprint)
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
