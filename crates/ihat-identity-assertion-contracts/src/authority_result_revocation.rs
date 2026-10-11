use serde::{Deserialize, Serialize};

use crate::RevocationCeremonyStateDto;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationMetadata {
    pub target_digest: String,
    pub previous_epoch: u64,
    pub current_epoch: u64,
    pub audit_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocationMetadata {
    pub target_digest: String,
    pub previous_device_epoch: u64,
    pub current_device_epoch: u64,
    pub revoked_session_count: u64,
    pub audit_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationCeremonyMetadata {
    pub attempt_id: String,
    pub finalize_command_id: String,
    pub target_digest: String,
    pub expires_at_epoch_s: u64,
    pub independent_approval_required: bool,
    pub state: RevocationCeremonyStateDto,
    pub approval_nonce: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationApprovalMetadata {
    pub attempt_id: String,
    pub finalize_command_id: String,
    pub approval_count: u64,
    pub ready_to_finalize: bool,
    pub state: RevocationCeremonyStateDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRevocationMetadata {
    pub attempt_id: String,
    pub finalize_command_id: String,
    pub target_digest: String,
    pub expires_at_epoch_s: u64,
    pub state: RevocationCeremonyStateDto,
    pub approval_nonce: Option<String>,
}
