use serde::de::DeserializeOwned;

use crate::{
    AuthorityRequestV1, AuthorityResponseV1, AuthorityWireError, MAX_AUTHORITY_REQUEST_BYTES,
    MAX_AUTHORITY_RESPONSE_BYTES, authority_validation,
};

/// Decodes one bounded and closed authority request.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, trailing, unknown-field, or invalid requests.
pub fn decode_authority_request_strict(
    bytes: &[u8],
) -> Result<AuthorityRequestV1, AuthorityWireError> {
    let value = decode(bytes, MAX_AUTHORITY_REQUEST_BYTES)?;
    authority_validation::request(&value)?;
    Ok(value)
}

/// Decodes one bounded and closed signed authority response.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, trailing, unknown-field, or invalid responses.
pub fn decode_authority_response_strict(
    bytes: &[u8],
) -> Result<AuthorityResponseV1, AuthorityWireError> {
    let value = decode(bytes, MAX_AUTHORITY_RESPONSE_BYTES)?;
    authority_validation::response(&value)?;
    Ok(value)
}

fn decode<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T, AuthorityWireError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AuthorityWireError::InputTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| AuthorityWireError::ContractInvalid)
}
