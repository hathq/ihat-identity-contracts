use serde::{Deserialize, Serialize};

use crate::{CurrentDeviceStatusV1, DeviceIdentityAssertionV1};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEvidenceMetadata {
    pub assertion: DeviceIdentityAssertionV1,
    pub current_status: CurrentDeviceStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshUvRequestOptions {
    pub attempt_id: String,
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
    pub credential_id: String,
    pub timeout_ms: u64,
    pub expires_at_epoch_s: u64,
    pub command_binding_sha256: String,
}
