use crate::{
    CurrentDeviceStatusV1,
    canonical::{field_record, number_record},
};

#[must_use]
pub fn canonical_current_status_payload(value: &CurrentDeviceStatusV1) -> Vec<u8> {
    let epochs = &value.revocation_epochs;
    let mut output = b"IHAT-CURRENT-DEVICE-STATUS-V1\n".to_vec();
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
