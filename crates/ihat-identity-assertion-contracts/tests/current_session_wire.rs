use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1,
    EstablishDeviceIdentitySessionCommand, ExpectedCurrentSessionDto,
    decode_authority_request_strict,
};

fn command() -> serde_json::Value {
    serde_json::json!({
        "type": "establish_device_identity_session",
        "command_id": "current-session-command-a",
        "service_id": "service-a",
        "pairwise_subject": "psu_owner_a",
        "device_id": "device-a",
        "sender_key_fingerprint": "11".repeat(32),
        "proof_id": "session-proof-a",
        "expected_subject_epoch": 1,
        "expected_service_epoch": 2,
        "expected_device_epoch": 3,
        "expected_current_session": {
            "state": "present",
            "session_ref": format!("sref_{}", "a".repeat(64)),
            "session_epoch": 4
        }
    })
}

fn request(command: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": AUTHORITY_REQUEST_SCHEMA,
        "request_id": "current-session-request-a",
        "command": command,
        "evidence": []
    }))
    .expect("json")
}

#[test]
fn device_identity_session_establishment_is_an_additive_closed_cas_command() {
    let decoded = decode_authority_request_strict(&request(&command())).expect("current session");
    assert_eq!(
        decoded.command.type_name(),
        "establish_device_identity_session"
    );
    let AuthorityCommand::EstablishDeviceIdentitySession(value) = decoded.command else {
        panic!("device identity session rotation command");
    };
    assert_eq!(
        value,
        EstablishDeviceIdentitySessionCommand {
            command_id: "current-session-command-a".into(),
            service_id: "service-a".into(),
            pairwise_subject: "psu_owner_a".into(),
            device_id: "device-a".into(),
            sender_key_fingerprint: "11".repeat(32),
            proof_id: "session-proof-a".into(),
            expected_subject_epoch: 1,
            expected_service_epoch: 2,
            expected_device_epoch: 3,
            expected_current_session: ExpectedCurrentSessionDto::Present {
                session_ref: format!("sref_{}", "a".repeat(64)),
                session_epoch: 4,
            },
        }
    );
}

#[test]
fn device_identity_session_establishment_requires_every_field_and_no_slot_override() {
    for field in [
        "command_id",
        "service_id",
        "pairwise_subject",
        "device_id",
        "sender_key_fingerprint",
        "proof_id",
        "expected_subject_epoch",
        "expected_service_epoch",
        "expected_device_epoch",
        "expected_current_session",
    ] {
        let mut value = command();
        value.as_object_mut().expect("object").remove(field);
        assert!(
            serde_json::from_slice::<AuthorityRequestV1>(&request(&value)).is_err(),
            "{field}"
        );
    }
    for field in ["unknown", "slot", "session_id", "session_ref", "account_id"] {
        let mut value = command();
        value
            .as_object_mut()
            .expect("object")
            .insert(field.into(), "forbidden".into());
        assert!(
            serde_json::from_slice::<AuthorityRequestV1>(&request(&value)).is_err(),
            "{field}"
        );
    }
}

#[test]
fn absent_and_present_cas_states_are_closed_and_exact() {
    let mut absent = command();
    absent["expected_current_session"] = serde_json::json!({"state":"absent"});
    let decoded = decode_authority_request_strict(&request(&absent)).expect("absent CAS");
    let AuthorityCommand::EstablishDeviceIdentitySession(value) = decoded.command else {
        panic!("establish command");
    };
    assert_eq!(
        value.expected_current_session,
        ExpectedCurrentSessionDto::Absent {}
    );

    for (label, invalid) in [
        (
            "absent-extra",
            serde_json::json!({"state":"absent","session_ref":"forbidden"}),
        ),
        (
            "present-missing",
            serde_json::json!({"state":"present","session_epoch":1}),
        ),
        (
            "present-invalid",
            serde_json::json!({"state":"present","session_ref":"bad","session_epoch":0}),
        ),
        ("unknown-state", serde_json::json!({"state":"unknown"})),
    ] {
        let mut value = command();
        value["expected_current_session"] = invalid;
        assert!(
            decode_authority_request_strict(&request(&value)).is_err(),
            "{label}"
        );
    }
}
