use serde::{Deserialize, Serialize};

use crate::AuthorityWireError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpectedCurrentSessionDto {
    Absent {},
    Present {
        session_ref: String,
        session_epoch: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EstablishDeviceIdentitySessionCommand {
    pub command_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub sender_key_fingerprint: String,
    pub proof_id: String,
    pub expected_subject_epoch: u64,
    pub expected_service_epoch: u64,
    pub expected_device_epoch: u64,
    pub expected_current_session: ExpectedCurrentSessionDto,
}

pub(crate) fn validate(
    value: &EstablishDeviceIdentitySessionCommand,
) -> Result<(), AuthorityWireError> {
    let ids = [
        &value.command_id,
        &value.service_id,
        &value.pairwise_subject,
        &value.device_id,
        &value.proof_id,
    ];
    if ids.iter().any(|value| !identifier(value))
        || value.command_id == value.proof_id
        || !lower_hex_32(&value.sender_key_fingerprint)
        || [
            value.expected_subject_epoch,
            value.expected_service_epoch,
            value.expected_device_epoch,
        ]
        .contains(&0)
        || !valid_expected(&value.expected_current_session)
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    Ok(())
}

fn valid_expected(value: &ExpectedCurrentSessionDto) -> bool {
    match value {
        ExpectedCurrentSessionDto::Absent {} => true,
        ExpectedCurrentSessionDto::Present {
            session_ref,
            session_epoch,
        } => *session_epoch > 0 && opaque_session_ref(session_ref),
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn lower_hex_32(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}

fn opaque_session_ref(value: &str) -> bool {
    value.len() == 69 && value.starts_with("sref_") && value[5..].bytes().all(lower_hex)
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}
