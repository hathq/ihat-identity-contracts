use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatorKindDto {
    DeviceBoundPasskey,
    SyncedPasskey,
    IndependentRecovery,
}

impl AuthenticatorKindDto {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceBoundPasskey => "device_bound_passkey",
            Self::SyncedPasskey => "synced_passkey",
            Self::IndependentRecovery => "independent_recovery",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshAuthenticationDto {
    pub proof_id: String,
    pub authenticator_id: String,
    pub authenticator_key_fingerprint: String,
    pub kind: AuthenticatorKindDto,
    pub user_verified: bool,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub service_id: String,
    pub pairwise_subject: String,
    pub session_ref: String,
    pub operation_digest_sha256: String,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub device_epoch: u64,
    pub session_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIdentityDto {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkIdentityCommand {
    pub command_id: String,
    pub account_ref: String,
    pub incoming_identity: ExternalIdentityDto,
    pub existing_authentication: FreshAuthenticationDto,
    pub incoming_authentication: FreshAuthenticationDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceAccountCommand {
    pub command_id: String,
    pub account_ref: String,
    pub service_id: String,
    pub expected_subject_epoch: u64,
    pub authentication: FreshAuthenticationDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloseServiceAccountCommand {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub expected_service_epoch: u64,
    pub authentication: FreshAuthenticationDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadSecretFreeProjectionCommand {
    pub account_ref: String,
    pub authentication: FreshAuthenticationDto,
}
