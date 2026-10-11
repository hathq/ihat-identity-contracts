use serde::Serialize;

use crate::{
    AuthorityCommand, AuthorityRequestV1, AuthorityResponseV1, AuthorityWireError, FreshUvV1,
    SignedEvidenceV1, authority_crypto,
};

pub const AUTHORITY_COMMAND_DOMAIN: &[u8] = b"ihat.identity.authority-host.command.v1\0";
pub const AUTHORITY_PREPARED_OPERATION_DOMAIN: &[u8] =
    b"ihat.identity.authority-host.prepared-operation.v1\0";
pub const SIGNED_EVIDENCE_DOMAIN: &[u8] = b"ihat.identity.authority-host.evidence.v1\0";
pub const FRESH_UV_DOMAIN: &[u8] = b"ihat.identity.authority-host.fresh-uv.v1\0";
pub const AUTHORITY_RESPONSE_DOMAIN: &[u8] = b"ihat.identity.authority-host.response.v1\0";

#[derive(Serialize)]
struct BindingView<'a> {
    schema: &'a str,
    request_id: &'a str,
    command: &'a AuthorityCommand,
}

/// Returns the RFC 8785/JCS request binding view, excluding evidence.
///
/// # Errors
///
/// Returns an error if the closed DTO cannot be canonically encoded.
pub fn command_jcs(value: &AuthorityRequestV1) -> Result<Vec<u8>, AuthorityWireError> {
    authority_crypto::jcs(&BindingView {
        schema: &value.schema,
        request_id: &value.request_id,
        command: &value.command,
    })
}

/// Returns the domain-separated SHA-256 command digest.
///
/// # Errors
///
/// Returns an error if the closed request cannot be canonically encoded.
pub fn command_digest(value: &AuthorityRequestV1) -> Result<String, AuthorityWireError> {
    let mut payload = Vec::from(AUTHORITY_COMMAND_DOMAIN);
    payload.extend(command_jcs(value)?);
    Ok(authority_crypto::sha256_hex(&payload))
}

/// Returns the authentication-free prepared operation digest.
///
/// # Errors
///
/// Returns an error if the command cannot be canonically encoded.
pub fn prepared_operation_digest(command: &AuthorityCommand) -> Result<String, AuthorityWireError> {
    let mut value =
        serde_json::to_value(command).map_err(|_| AuthorityWireError::CanonicalInvalid)?;
    crate::authority_authentication::strip(&mut value);
    let mut payload = Vec::from(AUTHORITY_PREPARED_OPERATION_DOMAIN);
    payload.extend(authority_crypto::jcs(&value)?);
    Ok(authority_crypto::sha256_hex(&payload))
}

/// Returns the domain-separated, length-framed evidence signing bytes.
///
/// # Errors
///
/// Returns an error if a field cannot be represented by the framing contract.
pub fn canonical_signed_evidence(value: &SignedEvidenceV1) -> Result<Vec<u8>, AuthorityWireError> {
    authority_crypto::framed(
        SIGNED_EVIDENCE_DOMAIN,
        &[
            &value.schema,
            value.role.as_str(),
            &value.proof_id,
            &value.key_id,
            &value.issued_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
            &value.binding_sha256,
        ],
    )
}

/// Returns the domain-separated, length-framed fresh-UV signing bytes.
///
/// # Errors
///
/// Returns an error if a field cannot be represented by the framing contract.
pub fn canonical_fresh_uv(value: &FreshUvV1) -> Result<Vec<u8>, AuthorityWireError> {
    authority_crypto::framed(
        FRESH_UV_DOMAIN,
        &[
            &value.schema,
            &value.proof_id,
            &value.credential_id,
            &value.authenticator_key_fingerprint,
            value.kind.as_str(),
            if value.user_verified { "true" } else { "false" },
            &value.issued_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
            &value.challenge,
            &value.attempt_id,
            &value.identity_nonce,
            &value.source_device_id,
            &value.service_id,
            &value.pairwise_subject,
            &value.session_ref,
            &value.operation_digest_sha256,
            &value.subject_epoch.to_string(),
            &value.service_epoch.to_string(),
            &value.device_epoch.to_string(),
            &value.session_epoch.to_string(),
            &value.account_binding_sha256,
            &value.key_id,
        ],
    )
}

/// Returns the domain-separated response signing bytes with a JCS outcome.
///
/// # Errors
///
/// Returns an error if the response cannot be canonically encoded or framed.
pub fn canonical_response(value: &AuthorityResponseV1) -> Result<Vec<u8>, AuthorityWireError> {
    let outcome = String::from_utf8(authority_crypto::jcs(&value.outcome)?)
        .map_err(|_| AuthorityWireError::CanonicalInvalid)?;
    authority_crypto::framed(
        AUTHORITY_RESPONSE_DOMAIN,
        &[
            &value.schema,
            &value.request_id,
            &value.command_type,
            &value.command_digest,
            &value.config_generation.to_string(),
            &value.issued_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
            &outcome,
            &value.key_id,
        ],
    )
}
