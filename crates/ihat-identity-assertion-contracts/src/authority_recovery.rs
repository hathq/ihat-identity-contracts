use crate::{DeviceProofKeyDto, FreshAuthenticationDto};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAuthorityKindDto {
    IndependentOfflineRecovery,
    IndependentBoundAuthenticator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApprovalDto {
    pub approval_id: String,
    pub authority_id: String,
    pub key_fingerprint: String,
    pub kind: RecoveryAuthorityKindDto,
    pub approved_at_epoch_s: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReplacementDto {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub proof_key: DeviceProofKeyDto,
    pub authentication: FreshAuthenticationDto,
    pub expected_subject_epoch: u64,
    pub expected_service_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverDeviceCommand {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub affected_device_id: String,
    pub replacement: RecoveryReplacementDto,
    pub approvals: Vec<RecoveryApprovalDto>,
    pub expected_subject_epoch: u64,
}
