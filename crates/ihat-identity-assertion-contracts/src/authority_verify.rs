use crate::{
    AuthorityResponseBinding, AuthorityResponseV1, AuthorityWireError, FreshUvBinding, FreshUvV1,
    SignedEvidenceBinding, SignedEvidenceV1, authority_crypto, authority_validation,
    canonical_fresh_uv, canonical_response, canonical_signed_evidence,
};

/// Verifies a closed evidence document against an exact proof and command binding.
///
/// # Errors
///
/// Rejects malformed, mismatched, stale, future, or incorrectly signed evidence.
pub fn verify_signed_evidence_at(
    value: &SignedEvidenceV1,
    expected: &SignedEvidenceBinding<'_>,
    expected_key_id: &str,
    public_key_hex: &str,
    now_epoch_s: u64,
) -> Result<(), AuthorityWireError> {
    authority_validation::signed_evidence(value)?;
    if value.role != expected.role
        || value.proof_id != expected.proof_id
        || value.binding_sha256 != expected.binding_sha256
        || value.key_id != expected_key_id
    {
        return Err(AuthorityWireError::ContextMismatch);
    }
    current(
        value.issued_at_epoch_s,
        value.expires_at_epoch_s,
        now_epoch_s,
    )?;
    authority_crypto::verify_hex(
        public_key_hex,
        &canonical_signed_evidence(value)?,
        &value.signature,
    )
}

/// Verifies fresh user verification against all durable ceremony bindings.
///
/// # Errors
///
/// Rejects malformed, mismatched, stale, future, or incorrectly signed documents.
pub fn verify_fresh_uv_at(
    value: &FreshUvV1,
    expected: &FreshUvBinding<'_>,
    expected_key_id: &str,
    public_key_hex: &str,
    now_epoch_s: u64,
) -> Result<(), AuthorityWireError> {
    authority_validation::fresh_uv(value)?;
    if !fresh_uv_matches(value, expected) || value.key_id != expected_key_id {
        return Err(AuthorityWireError::ContextMismatch);
    }
    current(
        value.issued_at_epoch_s,
        value.expires_at_epoch_s,
        now_epoch_s,
    )?;
    authority_crypto::verify_hex(
        public_key_hex,
        &canonical_fresh_uv(value)?,
        &value.signature,
    )
}

/// Verifies a response against its request, pinned generation, key, and trusted time.
///
/// # Errors
///
/// Rejects malformed, replay-substituted, stale, future, rollback, or invalid signatures.
pub fn verify_authority_response_at(
    value: &AuthorityResponseV1,
    expected: &AuthorityResponseBinding<'_>,
    expected_key_id: &str,
    public_key_hex: &str,
    now_epoch_s: u64,
) -> Result<(), AuthorityWireError> {
    authority_validation::response(value)?;
    if value.request_id != expected.request_id
        || value.command_type != expected.command_type
        || value.command_digest != expected.command_digest
        || value.config_generation < expected.minimum_config_generation
        || value.key_id != expected_key_id
    {
        return Err(AuthorityWireError::ContextMismatch);
    }
    current(
        value.issued_at_epoch_s,
        value.expires_at_epoch_s,
        now_epoch_s,
    )?;
    authority_crypto::verify_hex(
        public_key_hex,
        &canonical_response(value)?,
        &value.signature,
    )
}

fn current(issued: u64, expires: u64, now: u64) -> Result<(), AuthorityWireError> {
    if now < issued || now >= expires {
        return Err(AuthorityWireError::TimeInvalid);
    }
    Ok(())
}

fn fresh_uv_matches(value: &FreshUvV1, expected: &FreshUvBinding<'_>) -> bool {
    value.proof_id == expected.proof_id
        && value.credential_id == expected.credential_id
        && value.authenticator_key_fingerprint == expected.authenticator_key_fingerprint
        && value.kind == expected.kind
        && value.challenge == expected.challenge
        && value.attempt_id == expected.attempt_id
        && value.identity_nonce == expected.identity_nonce
        && value.source_device_id == expected.source_device_id
        && value.service_id == expected.service_id
        && value.pairwise_subject == expected.pairwise_subject
        && value.session_ref == expected.session_ref
        && value.operation_digest_sha256 == expected.operation_digest_sha256
        && value.subject_epoch == expected.subject_epoch
        && value.service_epoch == expected.service_epoch
        && value.device_epoch == expected.device_epoch
        && value.session_epoch == expected.session_epoch
        && value.account_binding_sha256 == expected.account_binding_sha256
}
