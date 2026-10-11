use serde::{Deserialize, Serialize};

use crate::{DeviceMetadata, PendingRevocationMetadata, ServiceMetadata, SessionMetadata};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretFreeProjection {
    pub account_ref: String,
    pub subject_epoch: u64,
    pub services: Vec<ServiceMetadata>,
    pub devices: Vec<DeviceMetadata>,
    pub sessions: Vec<SessionMetadata>,
    pub pending_revocations: Vec<PendingRevocationMetadata>,
}
