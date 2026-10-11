use crate::{AssertionError, DeviceIdentityAssertionV1, canonical_assertion_payload, validation};

const MAXIMUM_WIRE_BYTES: usize = 16_384;

pub trait AssertionVerifier {
    fn verify(&self, key_id: &str, canonical_payload: &[u8], signature: &str) -> bool;
}

/// Decodes one bounded, closed assertion document.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unknown-field, or invalid assertions.
pub fn decode_assertion_strict(bytes: &[u8]) -> Result<DeviceIdentityAssertionV1, AssertionError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_WIRE_BYTES {
        return Err(AssertionError::InputTooLarge);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| AssertionError::ContractInvalid)?;
    validation::assertion(&value)?;
    Ok(value)
}

/// Verifies the assertion signature and its exact consumer context at trusted time.
///
/// # Errors
///
/// Rejects invalid contracts, issuer or audience substitution, invalid time, and
/// signatures not accepted by the consumer's pinned verifier.
pub fn verify_assertion_at(
    value: &DeviceIdentityAssertionV1,
    verifier: &dyn AssertionVerifier,
    expected_issuer: &str,
    expected_audience: &str,
    now_epoch_s: u64,
) -> Result<(), AssertionError> {
    validation::assertion(value)?;
    if value.issuer != expected_issuer || value.audience != expected_audience {
        return Err(AssertionError::ContextMismatch);
    }
    if now_epoch_s < value.issued_at_epoch_s || now_epoch_s >= value.expires_at_epoch_s {
        return Err(AssertionError::TimeInvalid);
    }
    if !verifier.verify(
        &value.key_id,
        &canonical_assertion_payload(value),
        &value.signature,
    ) {
        return Err(AssertionError::SignatureInvalid);
    }
    Ok(())
}
