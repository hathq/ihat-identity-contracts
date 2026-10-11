use serde::Serialize;

use crate::{AuthorityWireError, MAX_AUTHORITY_STRING_BYTES};

const MAX_COLLECTION_ITEMS: usize = 1_024;

pub(crate) fn bounded_json<T: Serialize>(value: &T) -> Result<(), AuthorityWireError> {
    let value = serde_json::to_value(value).map_err(|_| AuthorityWireError::ContractInvalid)?;
    bounded_value(&value)
}

fn bounded_value(value: &serde_json::Value) -> Result<(), AuthorityWireError> {
    match value {
        serde_json::Value::String(value)
            if value.len() > MAX_AUTHORITY_STRING_BYTES || value.chars().any(char::is_control) =>
        {
            Err(AuthorityWireError::ContractInvalid)
        }
        serde_json::Value::Array(values) if values.len() > MAX_COLLECTION_ITEMS => {
            Err(AuthorityWireError::ContractInvalid)
        }
        serde_json::Value::Array(values) => values.iter().try_for_each(bounded_value),
        serde_json::Value::Object(values) => values.values().try_for_each(bounded_value),
        _ => Ok(()),
    }
}

pub(crate) fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
