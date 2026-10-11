use crate::FreshAuthenticationDto;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueSessionCommand {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub sender_key_fingerprint: String,
    pub proof_id: String,
    pub expected_subject_epoch: u64,
    pub expected_service_epoch: u64,
    pub expected_device_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeSessionCommand {
    pub proof_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_ref: String,
    pub sender_key_fingerprint: String,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub device_epoch: u64,
    pub session_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicRevocationTarget {
    Subject {
        account_ref: String,
    },
    ServiceAccount {
        service_id: String,
        pairwise_subject: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCommand {
    pub command_id: String,
    pub target: PublicRevocationTarget,
    pub expected_epoch: u64,
    pub authority_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeSessionByRefCommand {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub session_ref: String,
    pub expected_epoch: u64,
    pub authority_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeDeviceByRefCommand {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub target_device_id: String,
    pub expected_device_epoch: u64,
    pub authority_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginDeviceRevocationCommand {
    pub command_id: String,
    pub finalize_command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub source_device_id: String,
    pub source_session_ref: String,
    pub target_device_id: String,
    pub expected_device_epoch: u64,
    pub identity_nonce: String,
    pub sender_proof_id: String,
    pub authentication: FreshAuthenticationDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginSessionRevocationCommand {
    pub command_id: String,
    pub finalize_command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub source_device_id: String,
    pub source_session_ref: String,
    pub target_session_ref: String,
    pub expected_session_epoch: u64,
    pub identity_nonce: String,
    pub sender_proof_id: String,
    pub authentication: FreshAuthenticationDto,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRoleDto {
    RevocationAuthority,
    RecoveryApproval,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRevocationCommand {
    pub command_id: String,
    pub finalize_command_id: String,
    pub attempt_id: String,
    pub approval_nonce: String,
    pub approval_proof_id: String,
    pub approval_role: ApprovalRoleDto,
    pub authority_id: String,
    pub approver_device_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueIdentityEvidenceCommand {
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_ref: String,
    pub audience: String,
    pub nonce: String,
    pub ttl_seconds: u64,
    pub sender_key_fingerprint: String,
    pub sender_proof_id: String,
}
