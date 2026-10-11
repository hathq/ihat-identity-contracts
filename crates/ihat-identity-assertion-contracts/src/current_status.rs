use serde::{Deserialize, Serialize};

use crate::{
    AssertionError, AssertionVerifier, DeviceIdentityAssertionV1, DevicePostureV1,
    RevocationEpochsV1, canonical_current_status_payload, current_status_validation,
};

pub const CURRENT_DEVICE_STATUS_SCHEMA: &str = "ihat://identity/current-device-status/v1";
const MAXIMUM_WIRE_BYTES: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentDeviceStatusV1 {
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

/// Decode and validate one bounded, closed current-status document.
///
/// # Errors
/// Returns an assertion error when the wire document is malformed or invalid.
pub fn decode_current_status_strict(bytes: &[u8]) -> Result<CurrentDeviceStatusV1, AssertionError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_WIRE_BYTES {
        return Err(AssertionError::InputTooLarge);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| AssertionError::ContractInvalid)?;
    current_status_validation::status(&value)?;
    Ok(value)
}

/// Verify the status context, validity window, and detached signature.
///
/// # Errors
/// Returns an assertion error when validation or verification fails closed.
pub fn verify_current_status_at(
    value: &CurrentDeviceStatusV1,
    verifier: &dyn AssertionVerifier,
    expected_issuer: &str,
    expected_audience: &str,
    now_epoch_s: u64,
) -> Result<(), AssertionError> {
    current_status_validation::status(value)?;
    if value.issuer != expected_issuer || value.audience != expected_audience {
        return Err(AssertionError::ContextMismatch);
    }
    if now_epoch_s < value.issued_at_epoch_s || now_epoch_s >= value.expires_at_epoch_s {
        return Err(AssertionError::TimeInvalid);
    }
    if !verifier.verify(
        &value.key_id,
        &canonical_current_status_payload(value),
        &value.signature,
    ) {
        return Err(AssertionError::SignatureInvalid);
    }
    Ok(())
}

#[must_use]
pub fn current_status_matches_assertion(
    status: &CurrentDeviceStatusV1,
    assertion: &DeviceIdentityAssertionV1,
) -> bool {
    status.issuer == assertion.issuer
        && status.audience == assertion.audience
        && status.service_id == assertion.service_id
        && status.pairwise_subject == assertion.pairwise_subject
        && status.device_id == assertion.device_id
        && status.device_proof_key_ref == assertion.device_proof_key_ref
        && status.session_ref == assertion.session_ref
        && status.device_posture == assertion.device_posture
        && status.revocation_epochs == assertion.revocation_epochs
        && status.nonce == assertion.nonce
        && status.issued_at_epoch_s >= assertion.issued_at_epoch_s
        && status.expires_at_epoch_s <= assertion.expires_at_epoch_s
}
