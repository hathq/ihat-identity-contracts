use crate::{
    AuthorityWireError, SignedEvidenceBinding, SignedEvidenceV1, authority_crypto,
    authority_validation, canonical_signed_evidence,
};

/// Verifies an already accepted signed evidence document without reapplying its wall-clock TTL.
///
/// This is only suitable when the caller has independently established a durable, irreversible
/// acceptance that pins the exact evidence, command binding, role, and signing key.
///
/// # Errors
/// Rejects malformed, substituted, wrongly keyed, or incorrectly signed evidence.
pub fn verify_signed_evidence_historic(
    value: &SignedEvidenceV1,
    expected: &SignedEvidenceBinding<'_>,
    expected_key_id: &str,
    public_key_hex: &str,
) -> Result<(), AuthorityWireError> {
    authority_validation::signed_evidence(value)?;
    if value.role != expected.role
        || value.proof_id != expected.proof_id
        || value.binding_sha256 != expected.binding_sha256
        || value.key_id != expected_key_id
    {
        return Err(AuthorityWireError::ContextMismatch);
    }
    authority_crypto::verify_hex(
        public_key_hex,
        &canonical_signed_evidence(value)?,
        &value.signature,
    )
}
