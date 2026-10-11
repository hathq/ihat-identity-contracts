use ed25519_dalek::VerifyingKey;
use ihat_identity_assertion_contracts::*;

use crate::authority_wire_support::{fixture, signed_uv, uv_binding};

#[test]
fn strict_decode_rejects_unknown_trailing_and_oversize_documents() {
    let fixture = fixture();
    let mut value = fixture["command_binding"]["request_json"].clone();
    value
        .as_object_mut()
        .expect("object")
        .insert("unknown".into(), true.into());
    assert_eq!(
        decode_authority_request_strict(&serde_json::to_vec(&value).expect("json")),
        Err(AuthorityWireError::ContractInvalid)
    );
    let mut trailing =
        serde_json::to_vec(&fixture["command_binding"]["request_json"]).expect("json");
    trailing.extend_from_slice(b" {}");
    assert_eq!(
        decode_authority_request_strict(&trailing),
        Err(AuthorityWireError::ContractInvalid)
    );
    assert_eq!(
        decode_authority_request_strict(&vec![b' '; MAX_AUTHORITY_REQUEST_BYTES + 1]),
        Err(AuthorityWireError::InputTooLarge)
    );
}

#[test]
fn normal_authority_wire_has_no_account_bootstrap_result() {
    let bootstrap = serde_json::json!({
        "type": "account_created",
        "account_ref": "account-ref:must-not-cross-runtime-wire",
        "subject_epoch": 1
    });
    assert!(serde_json::from_value::<AuthorityResult>(bootstrap).is_err());
}

#[test]
fn fresh_uv_verification_rejects_tamper_stale_future_wrong_key_and_context() {
    let now = 1_700_000_000;
    let (value, key) = signed_uv(now);
    let public = hex::encode(VerifyingKey::from(&key).to_bytes());
    verify_fresh_uv_at(&value, &uv_binding(&value), "fresh-key", &public, now + 1)
        .expect("valid fresh UV");
    let mut tampered = value.clone();
    tampered.device_epoch += 1;
    assert_eq!(
        verify_fresh_uv_at(
            &tampered,
            &uv_binding(&tampered),
            "fresh-key",
            &public,
            now + 1
        ),
        Err(AuthorityWireError::SignatureInvalid)
    );
    assert_eq!(
        verify_fresh_uv_at(&value, &uv_binding(&value), "fresh-key", &public, now + 120),
        Err(AuthorityWireError::TimeInvalid)
    );
    assert_eq!(
        verify_fresh_uv_at(&value, &uv_binding(&value), "fresh-key", &public, now - 1),
        Err(AuthorityWireError::TimeInvalid)
    );
    assert_eq!(
        verify_fresh_uv_at(&value, &uv_binding(&value), "wrong-key", &public, now + 1),
        Err(AuthorityWireError::ContextMismatch)
    );
    let mut wrong_context = uv_binding(&value);
    wrong_context.device_epoch += 1;
    assert_eq!(
        verify_fresh_uv_at(&value, &wrong_context, "fresh-key", &public, now + 1),
        Err(AuthorityWireError::ContextMismatch)
    );
}

#[test]
fn signed_evidence_verification_binds_role_proof_digest_key_and_time() {
    let fixture = fixture();
    let digest = fixture["command_binding"]["command_digest"]
        .as_str()
        .expect("digest");
    let evidence = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: "proof-fixture-01".into(),
        key_id: "session-fixture-key".into(),
        issued_at_epoch_s: 1_700_000_000,
        expires_at_epoch_s: 1_700_000_060,
        binding_sha256: digest.into(),
        signature: fixture["evidence"]["signature_hex"]
            .as_str()
            .expect("signature")
            .into(),
    };
    let binding = SignedEvidenceBinding {
        role: VerificationRole::SessionSender,
        proof_id: "proof-fixture-01",
        binding_sha256: digest,
    };
    verify_signed_evidence_at(
        &evidence,
        &binding,
        "session-fixture-key",
        fixture["evidence"]["public_key_hex"]
            .as_str()
            .expect("public"),
        1_700_000_030,
    )
    .expect("valid evidence");
    let wrong = SignedEvidenceBinding {
        role: VerificationRole::DevicePossession,
        proof_id: "proof-fixture-01",
        binding_sha256: digest,
    };
    assert_eq!(
        verify_signed_evidence_at(
            &evidence,
            &wrong,
            "session-fixture-key",
            fixture["evidence"]["public_key_hex"]
                .as_str()
                .expect("public"),
            1_700_000_030
        ),
        Err(AuthorityWireError::ContextMismatch)
    );
}
