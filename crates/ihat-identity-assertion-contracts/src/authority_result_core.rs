use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatusDto {
    Active,
    Revoked,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationCeremonyStateDto {
    AwaitingIndependentApproval,
    ReadyToFinalize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePostureStateDto {
    Compliant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceMetadata {
    pub service_id: String,
    pub pairwise_subject: String,
    pub service_epoch: u64,
    pub status: LifecycleStatusDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMetadata {
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub key_fingerprint: String,
    pub posture: DevicePostureStateDto,
    pub posture_revision: u64,
    pub device_epoch: u64,
    pub status: LifecycleStatusDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMetadata {
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_ref: String,
    pub session_epoch: u64,
    pub status: LifecycleStatusDto,
}
