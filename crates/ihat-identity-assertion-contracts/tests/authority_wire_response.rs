use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ihat_identity_assertion_contracts::{
    AUTHORITY_RESPONSE_SCHEMA, AuthorityRejectionCode, AuthorityResponseBinding,
    AuthorityResponseV1, AuthorityWireError, ResponseOutcome, canonical_response,
    decode_authority_response_strict, verify_authority_response_at,
};

#[test]
fn signed_response_binds_request_command_digest_generation_key_and_time() {
    let now = 1_700_000_000;
    let (value, key) = signed_response(now);
    let public = hex::encode(VerifyingKey::from(&key).to_bytes());
    verify_authority_response_at(
        &value,
        &binding(&value, 7),
        "response-key",
        &public,
        now + 1,
    )
    .expect("valid response");
    let mut tampered = value.clone();
    tampered.command_digest = "bb".repeat(32);
    assert_eq!(
        verify_authority_response_at(
            &tampered,
            &binding(&tampered, 7),
            "response-key",
            &public,
            now + 1
        ),
        Err(AuthorityWireError::SignatureInvalid)
    );
    assert_eq!(
        verify_authority_response_at(
            &value,
            &binding(&value, 7),
            "response-key",
            &public,
            now + 30
        ),
        Err(AuthorityWireError::TimeInvalid)
    );
    assert_eq!(
        verify_authority_response_at(
            &value,
            &binding(&value, 7),
            "response-key",
            &public,
            now - 1
        ),
        Err(AuthorityWireError::TimeInvalid)
    );
    assert_eq!(
        verify_authority_response_at(
            &value,
            &binding(&value, 8),
            "response-key",
            &public,
            now + 1
        ),
        Err(AuthorityWireError::ContextMismatch)
    );
    assert_eq!(
        verify_authority_response_at(&value, &binding(&value, 7), "wrong-key", &public, now + 1),
        Err(AuthorityWireError::ContextMismatch)
    );
}

#[test]
fn response_decoder_rejects_unknown_trailing_and_overlong_ttl() {
    let (value, _) = signed_response(1_700_000_000);
    let mut json = serde_json::to_value(&value).expect("json");
    json.as_object_mut()
        .expect("object")
        .insert("unknown".into(), true.into());
    assert_eq!(
        decode_authority_response_strict(&serde_json::to_vec(&json).expect("json")),
        Err(AuthorityWireError::ContractInvalid)
    );
    let mut trailing = serde_json::to_vec(&value).expect("json");
    trailing.extend_from_slice(b" {}");
    assert_eq!(
        decode_authority_response_strict(&trailing),
        Err(AuthorityWireError::ContractInvalid)
    );
    let mut long = value;
    long.expires_at_epoch_s += 1;
    assert_eq!(
        decode_authority_response_strict(&serde_json::to_vec(&long).expect("json")),
        Err(AuthorityWireError::TimeInvalid)
    );
}

fn signed_response(now: u64) -> (AuthorityResponseV1, SigningKey) {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let mut value = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: "request-a".into(),
        command_type: "reconcile".into(),
        command_digest: "aa".repeat(32),
        config_generation: 7,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 30,
        outcome: ResponseOutcome::Rejected {
            code: AuthorityRejectionCode::EvidenceRejected,
        },
        key_id: "response-key".into(),
        signature: String::new(),
    };
    value.signature = hex::encode(
        key.sign(&canonical_response(&value).expect("canonical"))
            .to_bytes(),
    );
    (value, key)
}

fn binding(value: &AuthorityResponseV1, minimum: u64) -> AuthorityResponseBinding<'_> {
    AuthorityResponseBinding {
        request_id: &value.request_id,
        command_type: &value.command_type,
        command_digest: &value.command_digest,
        minimum_config_generation: minimum,
    }
}
