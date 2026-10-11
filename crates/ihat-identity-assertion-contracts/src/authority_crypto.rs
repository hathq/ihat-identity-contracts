use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::AuthorityWireError;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], AuthorityWireError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuthorityWireError::ContractInvalid);
    }
    hex::decode(value)
        .map_err(|_| AuthorityWireError::ContractInvalid)?
        .try_into()
        .map_err(|_| AuthorityWireError::ContractInvalid)
}

pub(crate) fn verify_hex(
    public_key_hex: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), AuthorityWireError> {
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(public_key_hex)?)
        .map_err(|_| AuthorityWireError::ContractInvalid)?;
    let signature = Signature::from_bytes(&decode_hex::<64>(signature_hex)?);
    key.verify_strict(payload, &signature)
        .map_err(|_| AuthorityWireError::SignatureInvalid)
}

pub(crate) fn framed(domain: &[u8], fields: &[&str]) -> Result<Vec<u8>, AuthorityWireError> {
    let mut output = Vec::from(domain);
    for field in fields {
        let length =
            u32::try_from(field.len()).map_err(|_| AuthorityWireError::CanonicalInvalid)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(field.as_bytes());
    }
    Ok(output)
}

pub(crate) fn jcs<T: Serialize>(value: &T) -> Result<Vec<u8>, AuthorityWireError> {
    let value = serde_json::to_value(value).map_err(|_| AuthorityWireError::CanonicalInvalid)?;
    let mut output = String::new();
    write_jcs(&value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_jcs(value: &Value, output: &mut String) -> Result<(), AuthorityWireError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(
            &serde_json::to_string(value).map_err(|_| AuthorityWireError::CanonicalInvalid)?,
        ),
        Value::Array(values) => write_array(values, output)?,
        Value::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|_| AuthorityWireError::CanonicalInvalid)?,
                );
                output.push(':');
                write_jcs(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn write_array(values: &[Value], output: &mut String) -> Result<(), AuthorityWireError> {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write_jcs(value, output)?;
    }
    output.push(']');
    Ok(())
}
