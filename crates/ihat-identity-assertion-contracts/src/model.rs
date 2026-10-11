use serde::{Deserialize, Serialize};

pub const DEVICE_IDENTITY_ASSERTION_SCHEMA: &str = "ihat://identity/device-identity-assertion/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePostureV1 {
    pub state: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEpochsV1 {
    pub subject: u64,
    pub service: u64,
    pub device: u64,
    pub session: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentityAssertionV1 {
    pub schema: String,
    pub issuer: String,
    pub audience: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub device_proof_key_ref: String,
    pub session_ref: String,
    pub device_posture: DevicePostureV1,
    pub revocation_epochs: RevocationEpochsV1,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub nonce: String,
    pub key_id: String,
    pub signature: String,
}
