use ed25519_dalek::{Signature, VerifyingKey};
use ihat_identity_assertion_contracts::*;

use crate::authority_wire_support::fixture;

#[test]
fn command_jcs_digest_and_all_frozen_examples_conform() {
    let fixture = fixture();
    let bytes = serde_json::to_vec(&fixture["command_binding"]["request_json"]).expect("json");
    let request = decode_authority_request_strict(&bytes).expect("closed request");
    assert_eq!(
        String::from_utf8(command_jcs(&request).expect("jcs")).expect("utf8"),
        fixture["command_binding"]["jcs"]
            .as_str()
            .expect("fixture jcs")
    );
    assert_eq!(
        command_digest(&request).expect("digest"),
        fixture["command_binding"]["command_digest"]
            .as_str()
            .expect("fixture digest")
    );
    for key in [
        "begin_request",
        "finish_request",
        "reconcile_request",
        "begin_device_revocation_request",
        "approve_revocation_request",
        "final_device_revocation_request",
        "issue_identity_evidence_request",
    ] {
        let bytes = serde_json::to_vec(&fixture["examples"][key]).expect("json");
        decode_authority_request_strict(&bytes).unwrap_or_else(|error| panic!("{key}: {error}"));
    }
    for key in [
        "begin_result",
        "finish_result",
        "reconcile_committed_result",
        "begin_device_revocation_result",
        "approve_revocation_result",
        "final_device_revocation_result",
    ] {
        serde_json::from_value::<AuthorityResult>(fixture["examples"][key].clone())
            .unwrap_or_else(|error| panic!("{key}: {error}"));
    }
}

#[test]
fn evidence_and_response_canonical_bytes_match_shared_signatures() {
    let fixture = fixture();
    let evidence = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: "proof-fixture-01".into(),
        key_id: "session-fixture-key".into(),
        issued_at_epoch_s: 1_700_000_000,
        expires_at_epoch_s: 1_700_000_060,
        binding_sha256: fixture["command_binding"]["command_digest"]
            .as_str()
            .expect("digest")
            .into(),
        signature: fixture["evidence"]["signature_hex"]
            .as_str()
            .expect("signature")
            .into(),
    };
    let canonical = canonical_signed_evidence(&evidence).expect("canonical");
    assert_eq!(
        hex::encode(&canonical),
        fixture["evidence"]["canonical_hex"]
            .as_str()
            .expect("bytes")
    );
    verify_signature(&fixture["evidence"], &canonical);
    let response: AuthorityResponseV1 = serde_json::from_value(serde_json::json!({
        "schema": AUTHORITY_RESPONSE_SCHEMA, "request_id": "request-fixture-01",
        "command_type": "revoke_session_by_ref", "command_digest": fixture["command_binding"]["command_digest"],
        "config_generation": 7, "issued_at_epoch_s": 1_700_000_000_u64,
        "expires_at_epoch_s": 1_700_000_030_u64,
        "outcome": {"status":"committed","result":{"type":"revocation","target_digest":"aa".repeat(32),
            "previous_epoch":1,"current_epoch":2,"audit_sequence":7}},
        "key_id":"response-fixture-key", "signature": fixture["response"]["signature_hex"]
    })).expect("response dto");
    let canonical = canonical_response(&response).expect("canonical response");
    assert_eq!(
        hex::encode(&canonical),
        fixture["response"]["canonical_hex"]
            .as_str()
            .expect("bytes")
    );
    verify_signature(&fixture["response"], &canonical);
}

fn verify_signature(value: &serde_json::Value, canonical: &[u8]) {
    let public: [u8; 32] = hex::decode(value["public_key_hex"].as_str().expect("public"))
        .expect("hex")
        .try_into()
        .expect("public length");
    let signature: [u8; 64] = hex::decode(value["signature_hex"].as_str().expect("signature"))
        .expect("hex")
        .try_into()
        .expect("signature length");
    VerifyingKey::from_bytes(&public)
        .expect("public key")
        .verify_strict(canonical, &Signature::from_bytes(&signature))
        .expect("valid signature");
}
