use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityRequestV1, AuthorityResponseV1, AuthorityResult, ResponseOutcome,
    decode_authority_request_strict, decode_authority_response_strict,
};

use crate::authority_wire_support::fixture;

#[test]
fn begin_rejects_ids_that_cannot_cross_cancel_recovery() {
    let mut begin = request("begin_device_revocation_request");
    begin_device(&mut begin).finalize_command_id = "f".repeat(129);
    assert!(decode_request(&begin).is_err());
    begin_device(&mut begin).finalize_command_id = "f".repeat(128);
    assert!(decode_request(&begin).is_ok());
    begin_device(&mut begin).command_id = "c".repeat(512);
    assert!(decode_request(&begin).is_err());

    let mut session = session_request();
    let AuthorityCommand::BeginSessionRevocation(command) = &mut session.command else {
        unreachable!();
    };
    command.sender_proof_id = "p".repeat(129);
    assert!(decode_request(&session).is_err());
}

#[test]
fn approval_and_results_share_the_downstream_id_bound() {
    let mut request = request("approve_revocation_request");
    let AuthorityCommand::ApproveRevocation(command) = &mut request.command else {
        unreachable!();
    };
    command.attempt_id = "a".repeat(129);
    assert!(decode_request(&request).is_err());

    let mut response = response("begin_device_revocation_result");
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(result),
    } = &mut response.outcome
    else {
        unreachable!();
    };
    result.finalize_command_id = "f".repeat(129);
    assert!(decode_response(&response).is_err());
}

fn request(name: &str) -> AuthorityRequestV1 {
    serde_json::from_value(fixture()["examples"][name].clone()).expect("fixture request")
}

fn begin_device(
    value: &mut AuthorityRequestV1,
) -> &mut ihat_identity_assertion_contracts::BeginDeviceRevocationCommand {
    let AuthorityCommand::BeginDeviceRevocation(command) = &mut value.command else {
        unreachable!();
    };
    command
}

fn session_request() -> AuthorityRequestV1 {
    let mut value = fixture()["examples"]["begin_device_revocation_request"].clone();
    let command = value["command"].as_object_mut().expect("command object");
    command.insert("type".into(), "begin_session_revocation".into());
    command.insert("target_session_ref".into(), "session-target".into());
    command.insert("expected_session_epoch".into(), 1.into());
    command.remove("target_device_id");
    command.remove("expected_device_epoch");
    serde_json::from_value(value).expect("session request")
}

fn response(name: &str) -> AuthorityResponseV1 {
    let result: AuthorityResult =
        serde_json::from_value(fixture()["examples"][name].clone()).expect("fixture result");
    AuthorityResponseV1 {
        schema: ihat_identity_assertion_contracts::AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: "response-a".into(),
        command_type: "begin_device_revocation".into(),
        command_digest: "11".repeat(32),
        config_generation: 1,
        issued_at_epoch_s: 10,
        expires_at_epoch_s: 40,
        outcome: ResponseOutcome::Committed { result },
        key_id: "response-key".into(),
        signature: "22".repeat(64),
    }
}

fn decode_request(
    value: &AuthorityRequestV1,
) -> Result<AuthorityRequestV1, ihat_identity_assertion_contracts::AuthorityWireError> {
    decode_authority_request_strict(&serde_json::to_vec(value).expect("request wire"))
}

fn decode_response(
    value: &AuthorityResponseV1,
) -> Result<AuthorityResponseV1, ihat_identity_assertion_contracts::AuthorityWireError> {
    decode_authority_response_strict(&serde_json::to_vec(value).expect("response wire"))
}
