use crate::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_MAX_TTL_SECONDS, AUTHORITY_RESPONSE_SCHEMA,
    AuthorityEvidence, AuthorityRequestV1, AuthorityResponseV1, AuthorityWireError,
    FRESH_UV_MAX_TTL_SECONDS, FRESH_UV_SCHEMA, FreshUvV1, MAX_AUTHORITY_EVIDENCE_ITEMS,
    ResponseOutcome, SIGNED_EVIDENCE_MAX_TTL_SECONDS, SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1,
    authority_bounds::{bounded_json, identifier, lower_hex},
};

const MAX_IDENTIFIER_BYTES: usize = 512;

pub(crate) fn request(value: &AuthorityRequestV1) -> Result<(), AuthorityWireError> {
    if value.schema != AUTHORITY_REQUEST_SCHEMA
        || !identifier(&value.request_id, 128)
        || value.evidence.len() > MAX_AUTHORITY_EVIDENCE_ITEMS
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    bounded_json(value)?;
    if let crate::AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &value.command {
        crate::authority_current_identity::validate(command)?;
    }
    if let crate::AuthorityCommand::EstablishDeviceIdentitySession(command) = &value.command {
        crate::authority_current_session::validate(command)?;
    }
    if let crate::AuthorityCommand::CancelPendingRevocation(command) = &value.command {
        crate::authority_revocation_cancel::validate_command(command)?;
    }
    if let crate::AuthorityCommand::AcknowledgePendingCancellation(command) = &value.command {
        crate::authority_revocation_cancel::validate_acknowledge_command(command)?;
    }
    crate::authority_revocation_validation::command(&value.command)?;
    for evidence in &value.evidence {
        match evidence {
            AuthorityEvidence::Signed(value) => signed_evidence(value)?,
            AuthorityEvidence::FreshUv(value) => fresh_uv(value)?,
        }
    }
    Ok(())
}

pub(crate) fn response(value: &AuthorityResponseV1) -> Result<(), AuthorityWireError> {
    if value.schema != AUTHORITY_RESPONSE_SCHEMA
        || !identifier(&value.request_id, 128)
        || !identifier(&value.command_type, 64)
        || !lower_hex(&value.command_digest, 32)
        || value.config_generation == 0
        || !identifier(&value.key_id, 128)
        || !lower_hex(&value.signature, 64)
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    valid_window(
        value.issued_at_epoch_s,
        value.expires_at_epoch_s,
        AUTHORITY_RESPONSE_MAX_TTL_SECONDS,
    )?;
    if let ResponseOutcome::Unknown { reconcile_digest } = &value.outcome
        && !lower_hex(reconcile_digest, 32)
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    if let ResponseOutcome::Committed {
        result: crate::AuthorityResult::PendingRevocationCancelled(result),
    } = &value.outcome
        && crate::authority_revocation_cancel::validate_result(result).is_err()
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    if let ResponseOutcome::Committed {
        result: crate::AuthorityResult::PendingCancellationAcknowledged(result),
    } = &value.outcome
        && crate::authority_revocation_cancel::validate_acknowledge_result(result).is_err()
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    if let ResponseOutcome::Committed { result } = &value.outcome {
        crate::authority_revocation_validation::result(result)?;
    }
    bounded_json(value)
}

pub(crate) fn signed_evidence(value: &SignedEvidenceV1) -> Result<(), AuthorityWireError> {
    if value.schema != SIGNED_EVIDENCE_SCHEMA
        || !identifier(&value.proof_id, 128)
        || !identifier(&value.key_id, 128)
        || !lower_hex(&value.binding_sha256, 32)
        || !lower_hex(&value.signature, 64)
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    valid_window(
        value.issued_at_epoch_s,
        value.expires_at_epoch_s,
        SIGNED_EVIDENCE_MAX_TTL_SECONDS,
    )
}

pub(crate) fn fresh_uv(value: &FreshUvV1) -> Result<(), AuthorityWireError> {
    let identifiers = [
        &value.proof_id,
        &value.credential_id,
        &value.challenge,
        &value.attempt_id,
        &value.identity_nonce,
        &value.source_device_id,
        &value.service_id,
        &value.pairwise_subject,
        &value.session_ref,
        &value.key_id,
    ];
    if value.schema != FRESH_UV_SCHEMA
        || identifiers
            .iter()
            .any(|value| !identifier(value, MAX_IDENTIFIER_BYTES))
        || !value.user_verified
        || !lower_hex(&value.authenticator_key_fingerprint, 32)
        || !lower_hex(&value.operation_digest_sha256, 32)
        || !lower_hex(&value.account_binding_sha256, 32)
        || !lower_hex(&value.signature, 64)
        || [
            value.subject_epoch,
            value.service_epoch,
            value.device_epoch,
            value.session_epoch,
        ]
        .contains(&0)
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    valid_window(
        value.issued_at_epoch_s,
        value.expires_at_epoch_s,
        FRESH_UV_MAX_TTL_SECONDS,
    )
}

fn valid_window(issued: u64, expires: u64, maximum: u64) -> Result<(), AuthorityWireError> {
    let lifetime = expires
        .checked_sub(issued)
        .ok_or(AuthorityWireError::TimeInvalid)?;
    if !(1..=maximum).contains(&lifetime) {
        return Err(AuthorityWireError::TimeInvalid);
    }
    Ok(())
}
