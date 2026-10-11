use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1,
    IssueCurrentDeviceIdentityEvidenceCommand, command_digest, decode_authority_request_strict,
};

fn command() -> serde_json::Value {
    serde_json::json!({
        "type": "issue_current_device_identity_evidence",
        "service_id": "service-a",
        "pairwise_subject": "psu_owner_a",
        "device_id": "device-a",
        "audience": "crowsi-device-agent",
        "identity_nonce": "identity-nonce-a",
        "ttl_seconds": 30,
        "session_sender_key_fingerprint": "11".repeat(32),
        "session_sender_proof_id": "session-proof-a"
    })
}

fn request(command: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema": AUTHORITY_REQUEST_SCHEMA,
        "request_id": "current-identity-request-a",
        "command": command,
        "evidence": []
    })
}

#[test]
fn current_identity_command_is_closed_and_contains_no_runtime_locator() {
    let wire = serde_json::to_vec(&request(&command())).expect("json");
    let decoded = decode_authority_request_strict(&wire).expect("closed current command");
    assert_eq!(
        decoded.command.type_name(),
        "issue_current_device_identity_evidence"
    );
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(value) = decoded.command else {
        panic!("current identity command");
    };
    assert_eq!(
        value,
        IssueCurrentDeviceIdentityEvidenceCommand {
            service_id: "service-a".into(),
            pairwise_subject: "psu_owner_a".into(),
            device_id: "device-a".into(),
            audience: "crowsi-device-agent".into(),
            identity_nonce: "identity-nonce-a".into(),
            ttl_seconds: 30,
            session_sender_key_fingerprint: "11".repeat(32),
            session_sender_proof_id: "session-proof-a".into(),
        }
    );
    let json = serde_json::to_string(&value).expect("json");
    for forbidden in ["account_id", "session_id", "session_ref"] {
        assert!(!json.contains(forbidden), "forbidden locator {forbidden}");
    }
}

#[test]
fn every_current_identity_field_is_required_and_unknown_locator_fields_fail() {
    for field in [
        "service_id",
        "pairwise_subject",
        "device_id",
        "audience",
        "identity_nonce",
        "ttl_seconds",
        "session_sender_key_fingerprint",
        "session_sender_proof_id",
    ] {
        let mut value = command();
        value.as_object_mut().expect("object").remove(field);
        assert!(
            serde_json::from_value::<AuthorityRequestV1>(request(&value)).is_err(),
            "{field}"
        );
    }
    for field in ["unknown", "account_id", "session_id", "session_ref"] {
        let mut value = command();
        value
            .as_object_mut()
            .expect("object")
            .insert(field.into(), "forbidden".into());
        assert!(
            serde_json::from_value::<AuthorityRequestV1>(request(&value)).is_err(),
            "{field}"
        );
    }
}

#[test]
fn current_identity_digest_binds_nonce_sender_proof_and_fingerprint() {
    let base: AuthorityRequestV1 = serde_json::from_value(request(&command())).expect("request");
    let digest = command_digest(&base).expect("digest");
    for field in [
        "identity_nonce",
        "session_sender_proof_id",
        "session_sender_key_fingerprint",
    ] {
        let mut changed = command();
        changed
            .as_object_mut()
            .expect("object")
            .insert(field.into(), "changed".into());
        let changed: AuthorityRequestV1 =
            serde_json::from_value(request(&changed)).expect("request");
        assert_ne!(command_digest(&changed).expect("digest"), digest, "{field}");
    }
}

#[test]
fn current_identity_semantics_reject_invalid_ttl_fingerprint_and_aliases() {
    for (field, invalid) in [
        ("ttl_seconds", serde_json::json!(0)),
        ("ttl_seconds", serde_json::json!(31)),
        (
            "session_sender_key_fingerprint",
            serde_json::json!("AA".repeat(32)),
        ),
        (
            "session_sender_key_fingerprint",
            serde_json::json!("11".repeat(31)),
        ),
        ("identity_nonce", serde_json::json!("")),
    ] {
        let mut value = command();
        value
            .as_object_mut()
            .expect("object")
            .insert(field.into(), invalid);
        let wire = serde_json::to_vec(&request(&value)).expect("json");
        assert!(decode_authority_request_strict(&wire).is_err(), "{field}");
    }
    let mut value = command();
    value["identity_nonce"] = value["session_sender_proof_id"].clone();
    let wire = serde_json::to_vec(&request(&value)).expect("json");
    assert!(decode_authority_request_strict(&wire).is_err());
}
