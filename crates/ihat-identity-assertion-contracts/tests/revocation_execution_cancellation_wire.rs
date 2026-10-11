use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityRequestV1,
    AuthorityResponseV1, AuthorityResult, CancelPendingRevocationCommand,
    PendingRevocationCancelledMetadata, ResponseOutcome, decode_authority_request_strict,
    decode_authority_response_strict,
};

fn command() -> CancelPendingRevocationCommand {
    CancelPendingRevocationCommand {
        command_id: "cancel-command-a".into(),
        finalize_command_id: "finalize-command-a".into(),
        attempt_id: "attempt-a".into(),
        opaque_owner_ref: "psa_owner_credential_scope_01".into(),
        service_id: "service-a".into(),
        pairwise_subject: "pairwise-a".into(),
        source_device_id: "device-a".into(),
        source_session_ref: "session-a".into(),
        target_digest_sha256: "11".repeat(32),
        begin_command_digest_sha256: "22".repeat(32),
        cancelled_state_revision: 7,
        authority_id: "revocation-cancellation-root".into(),
    }
}

#[test]
fn cancellation_command_and_result_are_closed() {
    let request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "request-a".into(),
        command: AuthorityCommand::CancelPendingRevocation(command()),
        evidence: vec![],
    };
    let wire = serde_json::to_vec(&request).expect("request wire");
    assert_eq!(
        decode_authority_request_strict(&wire).expect("request"),
        request
    );

    let response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: "request-a".into(),
        command_type: "cancel_pending_revocation".into(),
        command_digest: "33".repeat(32),
        config_generation: 1,
        issued_at_epoch_s: 10,
        expires_at_epoch_s: 40,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::PendingRevocationCancelled(
                PendingRevocationCancelledMetadata {
                    attempt_id: "attempt-a".into(),
                    finalize_command_id: "finalize-command-a".into(),
                    target_digest_sha256: "11".repeat(32),
                    cancellation_id: "44".repeat(32),
                },
            ),
        },
        key_id: "response-key".into(),
        signature: "55".repeat(64),
    };
    let wire = serde_json::to_vec(&response).expect("response wire");
    assert_eq!(
        decode_authority_response_strict(&wire).expect("response"),
        response
    );
}

#[test]
fn cancellation_rejects_zero_revision_and_open_fields() {
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "request-a".into(),
        command: AuthorityCommand::CancelPendingRevocation(command()),
        evidence: vec![],
    };
    let AuthorityCommand::CancelPendingRevocation(command) = &mut request.command else {
        unreachable!()
    };
    command.cancelled_state_revision = 0;
    let wire = serde_json::to_vec(&request).expect("cancellation request wire");
    assert!(decode_authority_request_strict(&wire).is_err());
    let mut open = serde_json::to_value(request).expect("json");
    open["command"]["unknown"] = true.into();
    assert!(serde_json::from_value::<AuthorityRequestV1>(open).is_err());
}
