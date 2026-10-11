use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ihat_identity_assertion_contracts::{
    AssertionError, AssertionVerifier, DeviceIdentityAssertionV1, DevicePostureV1,
    RevocationEpochsV1, canonical_assertion_payload, decode_assertion_strict, verify_assertion_at,
};

struct VerifierKey(VerifyingKey);

impl AssertionVerifier for VerifierKey {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        key_id == "identity-key:1" && self.0.verify(payload, &signature).is_ok()
    }
}

fn signed() -> (DeviceIdentityAssertionV1, VerifierKey) {
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut value = DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: "https://identity.example.test".into(),
        audience: "crowsi-policy-administrator".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise:crowsi:01".into(),
        device_id: "device:01".into(),
        device_proof_key_ref: "device-proof:sha256:abc".into(),
        session_ref: "sref_service_crowsi_01".into(),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 7,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 2,
            service: 3,
            device: 5,
            session: 8,
        },
        issued_at_epoch_s: 1_800_000_000,
        expires_at_epoch_s: 1_800_000_030,
        nonce: "nonce:01".into(),
        key_id: "identity-key:1".into(),
        signature: String::new(),
    };
    value.signature = hex::encode(key.sign(&canonical_assertion_payload(&value)).to_bytes());
    (value, VerifierKey(key.verifying_key()))
}

#[test]
fn exact_assertion_verifies_for_expected_context() {
    let (value, verifier) = signed();
    verify_assertion_at(
        &value,
        &verifier,
        "https://identity.example.test",
        "crowsi-policy-administrator",
        1_800_000_001,
    )
    .expect("verified assertion");
}

#[test]
fn context_substitution_expiry_and_signature_tamper_fail_closed() {
    let (value, verifier) = signed();
    for result in [
        verify_assertion_at(&value, &verifier, "wrong", &value.audience, 1_800_000_001),
        verify_assertion_at(&value, &verifier, &value.issuer, "wrong", 1_800_000_001),
        verify_assertion_at(
            &value,
            &verifier,
            &value.issuer,
            &value.audience,
            1_800_000_030,
        ),
    ] {
        assert!(result.is_err());
    }
    let mut changed = value;
    changed.device_id = "device:attacker".into();
    assert_eq!(
        verify_assertion_at(
            &changed,
            &verifier,
            &changed.issuer,
            &changed.audience,
            1_800_000_001,
        ),
        Err(AssertionError::SignatureInvalid)
    );
}

#[test]
fn strict_decoder_rejects_unknown_oversized_and_unbounded_values() {
    let (value, _) = signed();
    let encoded = serde_json::to_vec(&value).expect("encode");
    assert_eq!(decode_assertion_strict(&encoded).expect("decode"), value);
    let mut json = serde_json::to_value(&value).expect("value");
    json["account_id"] = "global-account-must-not-cross".into();
    assert!(decode_assertion_strict(&serde_json::to_vec(&json).expect("json")).is_err());
    assert_eq!(
        decode_assertion_strict(&vec![b'a'; 16_385]),
        Err(AssertionError::InputTooLarge)
    );
    let mut long_lived = value;
    long_lived.expires_at_epoch_s = long_lived.issued_at_epoch_s + 301;
    assert!(decode_assertion_strict(&serde_json::to_vec(&long_lived).expect("json")).is_err());
}

#[test]
fn strict_decoder_rejects_legacy_assertion_without_session_ref() {
    let (value, _) = signed();
    let mut legacy = serde_json::to_value(value).expect("value");
    legacy
        .as_object_mut()
        .expect("object")
        .remove("session_ref");
    assert!(decode_assertion_strict(&serde_json::to_vec(&legacy).expect("json")).is_err());
}

#[test]
fn canonical_payload_never_contains_signature_or_global_identity() {
    let (value, _) = signed();
    let canonical = String::from_utf8(canonical_assertion_payload(&value)).expect("utf8");
    assert!(!canonical.contains(&value.signature));
    assert!(!canonical.contains("account_id"));
    assert!(!canonical.contains("session_id"));
    assert!(canonical.contains("session_ref"));
    assert!(canonical.contains(&value.session_ref));
    assert!(canonical.starts_with("IHAT-DEVICE-IDENTITY-ASSERTION-V1\n"));
}
