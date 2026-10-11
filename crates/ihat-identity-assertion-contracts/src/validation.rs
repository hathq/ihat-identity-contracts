use crate::{AssertionError, DEVICE_IDENTITY_ASSERTION_SCHEMA, DeviceIdentityAssertionV1};

pub(crate) fn assertion(value: &DeviceIdentityAssertionV1) -> Result<(), AssertionError> {
    let lifetime = value
        .expires_at_epoch_s
        .checked_sub(value.issued_at_epoch_s)
        .ok_or(AssertionError::TimeInvalid)?;
    if value.schema != DEVICE_IDENTITY_ASSERTION_SCHEMA
        || value.device_posture.state != "compliant"
        || value.device_posture.revision == 0
        || !(1..=300).contains(&lifetime)
        || !identifier(&value.issuer, 512)
        || !identifier(&value.audience, 128)
        || !identifier(&value.service_id, 128)
        || !identifier(&value.pairwise_subject, 128)
        || !identifier(&value.device_id, 128)
        || !identifier(&value.device_proof_key_ref, 240)
        || !identifier(&value.session_ref, 128)
        || !identifier(&value.nonce, 128)
        || !identifier(&value.key_id, 128)
        || value.signature.is_empty()
        || value.signature.len() > 1_024
    {
        return Err(AssertionError::ContractInvalid);
    }
    Ok(())
}

pub(crate) fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && value.trim() == value
}
