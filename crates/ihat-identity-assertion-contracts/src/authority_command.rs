use serde::{Deserialize, Serialize};

use crate::{
    AcknowledgePendingCancellationCommand, ApproveRevocationCommand, AuthorityEvidence,
    AuthorizeSessionCommand, BeginDeviceRevocationCommand, BeginFreshUvCommand,
    BeginSessionRevocationCommand, CancelPendingRevocationCommand, CloseServiceAccountCommand,
    CreateServiceAccountCommand, EnrollDeviceCommand, EstablishDeviceIdentitySessionCommand,
    FinishFreshUvCommand, IssueCurrentDeviceIdentityEvidenceCommand, IssueIdentityEvidenceCommand,
    IssueSessionCommand, LinkIdentityCommand, ReadSecretFreeProjectionCommand, ReconcileCommand,
    RecoverDeviceCommand, RevokeCommand, RevokeDeviceByRefCommand, RevokeSessionByRefCommand,
    RotateDeviceKeyCommand,
};

pub const AUTHORITY_REQUEST_SCHEMA: &str = "ihat://identity/authority-host/request/v1";
pub const MAX_AUTHORITY_REQUEST_BYTES: usize = 262_144;
pub const MAX_AUTHORITY_RESPONSE_BYTES: usize = 262_144;
pub const MAX_AUTHORITY_EVIDENCE_ITEMS: usize = 16;
pub const MAX_AUTHORITY_STRING_BYTES: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityCommand {
    LinkIdentity(LinkIdentityCommand),
    CreateServiceAccount(CreateServiceAccountCommand),
    EnrollDevice(EnrollDeviceCommand),
    IssueSession(IssueSessionCommand),
    AuthorizeSession(AuthorizeSessionCommand),
    Revoke(RevokeCommand),
    RevokeSessionByRef(RevokeSessionByRefCommand),
    RevokeDeviceByRef(RevokeDeviceByRefCommand),
    BeginDeviceRevocation(BeginDeviceRevocationCommand),
    BeginSessionRevocation(BeginSessionRevocationCommand),
    ApproveRevocation(ApproveRevocationCommand),
    CancelPendingRevocation(CancelPendingRevocationCommand),
    AcknowledgePendingCancellation(AcknowledgePendingCancellationCommand),
    RecoverDevice(RecoverDeviceCommand),
    RotateDeviceKey(RotateDeviceKeyCommand),
    CloseServiceAccount(CloseServiceAccountCommand),
    IssueDeviceIdentityEvidence(IssueIdentityEvidenceCommand),
    IssueCurrentDeviceIdentityEvidence(IssueCurrentDeviceIdentityEvidenceCommand),
    EstablishDeviceIdentitySession(EstablishDeviceIdentitySessionCommand),
    BeginFreshUserVerification(BeginFreshUvCommand),
    FinishFreshUserVerification(FinishFreshUvCommand),
    Reconcile(ReconcileCommand),
    ReadSecretFreeProjection(ReadSecretFreeProjectionCommand),
}

impl AuthorityCommand {
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::LinkIdentity(_) => "link_identity",
            Self::CreateServiceAccount(_) => "create_service_account",
            Self::EnrollDevice(_) => "enroll_device",
            Self::IssueSession(_) => "issue_session",
            Self::AuthorizeSession(_) => "authorize_session",
            Self::Revoke(_) => "revoke",
            Self::RevokeSessionByRef(_) => "revoke_session_by_ref",
            Self::RevokeDeviceByRef(_) => "revoke_device_by_ref",
            Self::BeginDeviceRevocation(_) => "begin_device_revocation",
            Self::BeginSessionRevocation(_) => "begin_session_revocation",
            Self::ApproveRevocation(_) => "approve_revocation",
            Self::CancelPendingRevocation(_) => "cancel_pending_revocation",
            Self::AcknowledgePendingCancellation(_) => "acknowledge_pending_cancellation",
            Self::RecoverDevice(_) => "recover_device",
            Self::RotateDeviceKey(_) => "rotate_device_key",
            Self::CloseServiceAccount(_) => "close_service_account",
            Self::IssueDeviceIdentityEvidence(_) => "issue_device_identity_evidence",
            Self::IssueCurrentDeviceIdentityEvidence(_) => "issue_current_device_identity_evidence",
            Self::EstablishDeviceIdentitySession(_) => "establish_device_identity_session",
            Self::BeginFreshUserVerification(_) => "begin_fresh_user_verification",
            Self::FinishFreshUserVerification(_) => "finish_fresh_user_verification",
            Self::Reconcile(_) => "reconcile",
            Self::ReadSecretFreeProjection(_) => "read_secret_free_projection",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub command: AuthorityCommand,
    pub evidence: Vec<AuthorityEvidence>,
}
