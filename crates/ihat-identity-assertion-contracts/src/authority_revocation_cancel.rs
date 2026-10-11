use serde::{Deserialize, Serialize};

use crate::{AuthorityWireError, authority_bounds};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelPendingRevocationCommand {
    pub command_id: String,
    pub finalize_command_id: String,
    pub attempt_id: String,
    pub opaque_owner_ref: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub source_device_id: String,
    pub source_session_ref: String,
    pub target_digest_sha256: String,
    pub begin_command_digest_sha256: String,
    pub cancelled_state_revision: u64,
    pub authority_id: String,
}

pub(crate) fn validate_command(
    value: &CancelPendingRevocationCommand,
) -> Result<(), AuthorityWireError> {
    let identifiers = [
        &value.command_id,
        &value.finalize_command_id,
        &value.attempt_id,
        &value.opaque_owner_ref,
        &value.service_id,
        &value.pairwise_subject,
        &value.source_device_id,
        &value.source_session_ref,
        &value.authority_id,
    ];
    let valid = value.cancelled_state_revision > 0
        && identifiers
            .into_iter()
            .all(|item| authority_bounds::identifier(item, 512))
        && authority_bounds::lower_hex(&value.target_digest_sha256, 32)
        && authority_bounds::lower_hex(&value.begin_command_digest_sha256, 32);
    valid
        .then_some(())
        .ok_or(AuthorityWireError::ContractInvalid)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRevocationCancelledMetadata {
    pub attempt_id: String,
    pub finalize_command_id: String,
    pub target_digest_sha256: String,
    pub cancellation_id: String,
}

pub(crate) fn validate_result(
    value: &PendingRevocationCancelledMetadata,
) -> Result<(), AuthorityWireError> {
    let valid = authority_bounds::identifier(&value.attempt_id, 128)
        && authority_bounds::identifier(&value.finalize_command_id, 128)
        && authority_bounds::lower_hex(&value.target_digest_sha256, 32)
        && authority_bounds::lower_hex(&value.cancellation_id, 32);
    valid
        .then_some(())
        .ok_or(AuthorityWireError::ContractInvalid)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgePendingCancellationCommand {
    pub command_id: String,
    pub cancellation_id: String,
    pub cancel_pending_command_digest_sha256: String,
    pub cancel_pending_response_digest_sha256: String,
    pub source_device_id: String,
    pub cleanup_completed_revision: u64,
    pub authority_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingCancellationAcknowledgedMetadata {
    pub cancellation_id: String,
    pub cleanup_id: String,
}

pub(crate) fn validate_acknowledge_command(
    value: &AcknowledgePendingCancellationCommand,
) -> Result<(), AuthorityWireError> {
    let valid = authority_bounds::identifier(&value.command_id, 128)
        && authority_bounds::lower_hex(&value.cancellation_id, 32)
        && authority_bounds::lower_hex(&value.cancel_pending_command_digest_sha256, 32)
        && authority_bounds::lower_hex(&value.cancel_pending_response_digest_sha256, 32)
        && authority_bounds::identifier(&value.source_device_id, 128)
        && value.cleanup_completed_revision > 0
        && authority_bounds::identifier(&value.authority_id, 128);
    valid
        .then_some(())
        .ok_or(AuthorityWireError::ContractInvalid)
}

pub(crate) fn validate_acknowledge_result(
    value: &PendingCancellationAcknowledgedMetadata,
) -> Result<(), AuthorityWireError> {
    (authority_bounds::lower_hex(&value.cancellation_id, 32)
        && authority_bounds::lower_hex(&value.cleanup_id, 32))
    .then_some(())
    .ok_or(AuthorityWireError::ContractInvalid)
}
