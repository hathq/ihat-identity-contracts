use serde::{Deserialize, Serialize};

use crate::AuthenticatorKindDto;

pub const SIGNED_EVIDENCE_SCHEMA: &str = "ihat://identity/authority-host/signed-evidence/v1";
pub const FRESH_UV_SCHEMA: &str = "ihat://identity/authority-host/fresh-uv/v1";
pub const SIGNED_EVIDENCE_MAX_TTL_SECONDS: u64 = 120;
pub const FRESH_UV_MAX_TTL_SECONDS: u64 = 120;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRole {
    DeviceAttestation,
    DevicePossession,
    SessionSender,
    RevocationAuthority,
    RevocationExecutionReservation,
    RevocationExecutionCancellation,
    RevocationCancellationCleanup,
    RevocationCancellationCleanupComplete,
    RecoveryApproval,
}

impl VerificationRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceAttestation => "device_attestation",
            Self::DevicePossession => "device_possession",
            Self::SessionSender => "session_sender",
            Self::RevocationAuthority => "revocation_authority",
            Self::RevocationExecutionReservation => "revocation_execution_reservation",
            Self::RevocationExecutionCancellation => "revocation_execution_cancellation",
            Self::RevocationCancellationCleanup => "revocation_cancellation_cleanup",
            Self::RevocationCancellationCleanupComplete => {
                "revocation_cancellation_cleanup_complete"
            }
            Self::RecoveryApproval => "recovery_approval",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceV1 {
    pub schema: String,
    pub role: VerificationRole,
    pub proof_id: String,
    pub key_id: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub binding_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshUvV1 {
    pub schema: String,
    pub proof_id: String,
    pub credential_id: String,
    pub authenticator_key_fingerprint: String,
    pub kind: AuthenticatorKindDto,
    pub user_verified: bool,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub challenge: String,
    pub attempt_id: String,
    pub identity_nonce: String,
    pub source_device_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub session_ref: String,
    pub operation_digest_sha256: String,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub device_epoch: u64,
    pub session_epoch: u64,
    pub account_binding_sha256: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorityEvidence {
    Signed(SignedEvidenceV1),
    FreshUv(FreshUvV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEvidenceBinding<'a> {
    pub role: VerificationRole,
    pub proof_id: &'a str,
    pub binding_sha256: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshUvBinding<'a> {
    pub proof_id: &'a str,
    pub credential_id: &'a str,
    pub authenticator_key_fingerprint: &'a str,
    pub kind: AuthenticatorKindDto,
    pub challenge: &'a str,
    pub attempt_id: &'a str,
    pub identity_nonce: &'a str,
    pub source_device_id: &'a str,
    pub service_id: &'a str,
    pub pairwise_subject: &'a str,
    pub session_ref: &'a str,
    pub operation_digest_sha256: &'a str,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub device_epoch: u64,
    pub session_epoch: u64,
    pub account_binding_sha256: &'a str,
}
