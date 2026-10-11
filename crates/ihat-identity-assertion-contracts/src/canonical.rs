use crate::DeviceIdentityAssertionV1;

#[must_use]
pub fn canonical_assertion_payload(value: &DeviceIdentityAssertionV1) -> Vec<u8> {
    let epochs = &value.revocation_epochs;
    let mut output = b"IHAT-DEVICE-IDENTITY-ASSERTION-V1\n".to_vec();
    for (name, field) in [
        ("schema", value.schema.as_str()),
        ("issuer", value.issuer.as_str()),
        ("audience", value.audience.as_str()),
        ("service_id", value.service_id.as_str()),
        ("pairwise_subject", value.pairwise_subject.as_str()),
        ("device_id", value.device_id.as_str()),
        ("device_proof_key_ref", value.device_proof_key_ref.as_str()),
        ("session_ref", value.session_ref.as_str()),
        ("device_posture.state", value.device_posture.state.as_str()),
    ] {
        field_record(&mut output, name, field);
    }
    for (name, field) in [
        ("device_posture.revision", value.device_posture.revision),
        ("revocation.subject", epochs.subject),
        ("revocation.service", epochs.service),
        ("revocation.device", epochs.device),
        ("revocation.session", epochs.session),
        ("issued_at_epoch_s", value.issued_at_epoch_s),
        ("expires_at_epoch_s", value.expires_at_epoch_s),
    ] {
        number_record(&mut output, name, field);
    }
    field_record(&mut output, "nonce", &value.nonce);
    field_record(&mut output, "key_id", &value.key_id);
    output
}

pub(crate) fn number_record(output: &mut Vec<u8>, name: &str, value: u64) {
    field_record(output, name, &value.to_string());
}

pub(crate) fn field_record(output: &mut Vec<u8>, name: &str, value: &str) {
    output.extend_from_slice(name.len().to_string().as_bytes());
    output.push(b':');
    output.extend_from_slice(name.as_bytes());
    output.push(b':');
    output.extend_from_slice(value.len().to_string().as_bytes());
    output.push(b'\n');
    output.extend_from_slice(value.as_bytes());
    output.push(b'\n');
}
