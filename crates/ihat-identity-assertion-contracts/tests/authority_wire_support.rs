use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;
use serde_json::Value;

pub fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/wire-v1-fixture.json"))
        .expect("authoritative wire fixture")
}

pub fn signed_uv(now: u64) -> (FreshUvV1, SigningKey) {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let mut value = FreshUvV1 {
        schema: FRESH_UV_SCHEMA.into(),
        proof_id: "fresh-proof".into(),
        credential_id: "credential-a".into(),
        authenticator_key_fingerprint: "11".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 120,
        challenge: "challenge-a".into(),
        attempt_id: "attempt-a".into(),
        identity_nonce: "nonce-a".into(),
        source_device_id: "device-a".into(),
        service_id: "service-a".into(),
        pairwise_subject: "pairwise-a".into(),
        session_ref: format!("sref_{}", "a".repeat(64)),
        operation_digest_sha256: "22".repeat(32),
        subject_epoch: 1,
        service_epoch: 2,
        device_epoch: 3,
        session_epoch: 4,
        account_binding_sha256: "33".repeat(32),
        key_id: "fresh-key".into(),
        signature: String::new(),
    };
    value.signature = hex::encode(
        key.sign(&canonical_fresh_uv(&value).expect("canonical"))
            .to_bytes(),
    );
    (value, key)
}

pub fn uv_binding(value: &FreshUvV1) -> FreshUvBinding<'_> {
    FreshUvBinding {
        proof_id: &value.proof_id,
        credential_id: &value.credential_id,
        authenticator_key_fingerprint: &value.authenticator_key_fingerprint,
        kind: value.kind,
        challenge: &value.challenge,
        attempt_id: &value.attempt_id,
        identity_nonce: &value.identity_nonce,
        source_device_id: &value.source_device_id,
        service_id: &value.service_id,
        pairwise_subject: &value.pairwise_subject,
        session_ref: &value.session_ref,
        operation_digest_sha256: &value.operation_digest_sha256,
        subject_epoch: value.subject_epoch,
        service_epoch: value.service_epoch,
        device_epoch: value.device_epoch,
        session_epoch: value.session_epoch,
        account_binding_sha256: &value.account_binding_sha256,
    }
}
