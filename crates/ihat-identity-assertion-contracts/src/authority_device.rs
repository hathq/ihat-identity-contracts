use crate::FreshAuthenticationDto;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyCustodyDto {
    HardwareNonExportable,
    SoftwareNonExportable,
    Exportable,
    SyncedPasskey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProofKeyDto {
    pub fingerprint: String,
    pub spki_base64url: String,
    pub custody: DeviceKeyCustodyDto,
    pub attestation_base64url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollDeviceCommand {
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
pub struct RotateDeviceKeyCommand {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub retired_key_fingerprint: String,
    pub replacement_key: DeviceProofKeyDto,
    pub authentication: FreshAuthenticationDto,
    pub expected_device_epoch: u64,
}
