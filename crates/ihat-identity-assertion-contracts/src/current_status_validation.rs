use crate::{AssertionError, CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1};

pub(crate) fn status(value: &CurrentDeviceStatusV1) -> Result<(), AssertionError> {
    let lifetime = value
        .expires_at_epoch_s
        .checked_sub(value.issued_at_epoch_s)
        .ok_or(AssertionError::TimeInvalid)?;
    if value.schema != CURRENT_DEVICE_STATUS_SCHEMA
        || value.device_posture.state != "compliant"
        || value.device_posture.revision == 0
        || value.revocation_epochs.subject == 0
        || value.revocation_epochs.service == 0
        || value.revocation_epochs.device == 0
        || value.revocation_epochs.session == 0
        || !(1..=30).contains(&lifetime)
        || !crate::validation::identifier(&value.issuer, 512)
        || !crate::validation::identifier(&value.audience, 128)
        || !crate::validation::identifier(&value.service_id, 128)
        || !crate::validation::identifier(&value.pairwise_subject, 128)
        || !crate::validation::identifier(&value.device_id, 128)
        || !crate::validation::identifier(&value.device_proof_key_ref, 240)
        || !crate::validation::identifier(&value.session_ref, 128)
        || !crate::validation::identifier(&value.nonce, 128)
        || !crate::validation::identifier(&value.key_id, 128)
        || value.signature.is_empty()
        || value.signature.len() > 1_024
    {
        return Err(AssertionError::ContractInvalid);
    }
    Ok(())
}
