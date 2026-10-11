use crate::{
    ApproveRevocationCommand, AuthorityResult, AuthorityWireError, BeginDeviceRevocationCommand,
    BeginSessionRevocationCommand, FreshAuthenticationDto,
    authority_bounds::{identifier, lower_hex},
};

const MAX_ID: usize = 128;

pub(crate) fn command(value: &crate::AuthorityCommand) -> Result<(), AuthorityWireError> {
    match value {
        crate::AuthorityCommand::BeginDeviceRevocation(value) => begin_device(value),
        crate::AuthorityCommand::BeginSessionRevocation(value) => begin_session(value),
        crate::AuthorityCommand::ApproveRevocation(value) => approve(value),
        _ => Ok(()),
    }
}

pub(crate) fn begin_device(value: &BeginDeviceRevocationCommand) -> Result<(), AuthorityWireError> {
    let valid = identifiers([
        &value.command_id,
        &value.finalize_command_id,
        &value.service_id,
        &value.pairwise_subject,
        &value.source_device_id,
        &value.source_session_ref,
        &value.target_device_id,
        &value.identity_nonce,
        &value.sender_proof_id,
    ]) && value.expected_device_epoch > 0
        && authentication(&value.authentication);
    valid
        .then_some(())
        .ok_or(AuthorityWireError::ContractInvalid)
}

pub(crate) fn begin_session(
    value: &BeginSessionRevocationCommand,
) -> Result<(), AuthorityWireError> {
    let valid = identifiers([
        &value.command_id,
        &value.finalize_command_id,
        &value.service_id,
        &value.pairwise_subject,
        &value.source_device_id,
        &value.source_session_ref,
        &value.target_session_ref,
        &value.identity_nonce,
        &value.sender_proof_id,
    ]) && value.expected_session_epoch > 0
        && authentication(&value.authentication);
    valid
        .then_some(())
        .ok_or(AuthorityWireError::ContractInvalid)
}

pub(crate) fn approve(value: &ApproveRevocationCommand) -> Result<(), AuthorityWireError> {
    identifiers([
        &value.command_id,
        &value.finalize_command_id,
        &value.attempt_id,
        &value.approval_nonce,
        &value.approval_proof_id,
        &value.authority_id,
        &value.approver_device_id,
    ])
    .then_some(())
    .ok_or(AuthorityWireError::ContractInvalid)
}

pub(crate) fn result(value: &AuthorityResult) -> Result<(), AuthorityWireError> {
    let valid = match value {
        AuthorityResult::RevocationBegun(value) => {
            identifiers([&value.attempt_id, &value.finalize_command_id])
                && lower_hex(&value.target_digest, 32)
                && value.expires_at_epoch_s > 0
                && value
                    .approval_nonce
                    .as_ref()
                    .is_none_or(|item| identifier(item, MAX_ID))
        }
        AuthorityResult::RevocationApproved(value) => {
            identifiers([&value.attempt_id, &value.finalize_command_id])
                && value.approval_count == 1
        }
        AuthorityResult::PendingRevocationCancelled(value) => {
            crate::authority_revocation_cancel::validate_result(value).is_ok()
        }
        AuthorityResult::PendingCancellationAcknowledged(value) => {
            crate::authority_revocation_cancel::validate_acknowledge_result(value).is_ok()
        }
        AuthorityResult::Reconciled {
            original_command_digest,
            result,
        } => lower_hex(original_command_digest, 32) && self::result(result).is_ok(),
        _ => true,
    };
    valid
        .then_some(())
        .ok_or(AuthorityWireError::ContractInvalid)
}

fn authentication(value: &FreshAuthenticationDto) -> bool {
    identifiers([
        &value.proof_id,
        &value.authenticator_id,
        &value.service_id,
        &value.pairwise_subject,
        &value.session_ref,
    ]) && lower_hex(&value.authenticator_key_fingerprint, 32)
        && lower_hex(&value.operation_digest_sha256, 32)
        && value.user_verified
        && value.issued_at_epoch_s < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= crate::FRESH_UV_MAX_TTL_SECONDS
        && [
            value.subject_epoch,
            value.service_epoch,
            value.device_epoch,
            value.session_epoch,
        ]
        .into_iter()
        .all(|item| item > 0)
}

fn identifiers<const N: usize>(values: [&String; N]) -> bool {
    values.into_iter().all(|item| identifier(item, MAX_ID))
}
