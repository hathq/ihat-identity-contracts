//! Closed, implementation-independent device identity assertion contract.

mod authority_account;
mod authority_authentication;
mod authority_bounds;
mod authority_canonical;
mod authority_command;
mod authority_crypto;
mod authority_current_identity;
mod authority_current_session;
mod authority_decode;
mod authority_device;
mod authority_error;
mod authority_evidence;
mod authority_projection;
mod authority_recovery;
mod authority_response;
mod authority_result;
mod authority_result_core;
mod authority_result_evidence;
mod authority_result_revocation;
mod authority_revocation_cancel;
mod authority_revocation_validation;
mod authority_session;
mod authority_uv;
mod authority_validation;
mod authority_verify;
mod authority_verify_historic;
mod canonical;
mod current_status;
mod current_status_canonical;
mod current_status_validation;
mod error;
mod model;
mod validation;
mod verifier;

pub use authority_account::*;
pub use authority_canonical::{
    AUTHORITY_COMMAND_DOMAIN, AUTHORITY_PREPARED_OPERATION_DOMAIN, AUTHORITY_RESPONSE_DOMAIN,
    FRESH_UV_DOMAIN, SIGNED_EVIDENCE_DOMAIN, canonical_fresh_uv, canonical_response,
    canonical_signed_evidence, command_digest, command_jcs, prepared_operation_digest,
};
pub use authority_command::*;
pub use authority_current_identity::*;
pub use authority_current_session::*;
pub use authority_decode::{decode_authority_request_strict, decode_authority_response_strict};
pub use authority_device::*;
pub use authority_error::AuthorityWireError;
pub use authority_evidence::*;
pub use authority_projection::SecretFreeProjection;
pub use authority_recovery::*;
pub use authority_response::*;
pub use authority_result::AuthorityResult;
pub use authority_result_core::*;
pub use authority_result_evidence::*;
pub use authority_result_revocation::*;
pub use authority_revocation_cancel::*;
pub use authority_session::*;
pub use authority_uv::*;
pub use authority_verify::{
    verify_authority_response_at, verify_fresh_uv_at, verify_signed_evidence_at,
};
pub use authority_verify_historic::verify_signed_evidence_historic;
pub use canonical::canonical_assertion_payload;
pub use current_status::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, current_status_matches_assertion,
    decode_current_status_strict, verify_current_status_at,
};
pub use current_status_canonical::canonical_current_status_payload;
pub use error::AssertionError;
pub use model::{
    DEVICE_IDENTITY_ASSERTION_SCHEMA, DeviceIdentityAssertionV1, DevicePostureV1,
    RevocationEpochsV1,
};
pub use verifier::{AssertionVerifier, decode_assertion_strict, verify_assertion_at};
