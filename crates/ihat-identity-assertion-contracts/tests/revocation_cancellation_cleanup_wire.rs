use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AcknowledgePendingCancellationCommand,
    AuthorityCommand, AuthorityRequestV1, AuthorityResponseV1, AuthorityResult,
    PendingCancellationAcknowledgedMetadata, ResponseOutcome, decode_authority_request_strict,
    decode_authority_response_strict,
};

fn request() -> AuthorityRequestV1 {
    AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "cleanup-request-a".into(),
        command: AuthorityCommand::AcknowledgePendingCancellation(
            AcknowledgePendingCancellationCommand {
                command_id: "11".repeat(32),
                cancellation_id: "22".repeat(32),
                cancel_pending_command_digest_sha256: "33".repeat(32),
                cancel_pending_response_digest_sha256: "44".repeat(32),
                source_device_id: "device-a".into(),
                cleanup_completed_revision: 9,
                authority_id: "cancellation-cleanup-root".into(),
            },
        ),
        evidence: vec![],
    }
}

#[test]
fn cleanup_command_and_result_are_closed() {
    let request = request();
    let wire = serde_json::to_vec(&request).expect("request wire");
    assert_eq!(
        decode_authority_request_strict(&wire).expect("closed cleanup request"),
        request
    );

    let response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: "cleanup-request-a".into(),
        command_type: "acknowledge_pending_cancellation".into(),
        command_digest: "55".repeat(32),
        config_generation: 7,
        issued_at_epoch_s: 20,
        expires_at_epoch_s: 50,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::PendingCancellationAcknowledged(
                PendingCancellationAcknowledgedMetadata {
                    cancellation_id: "22".repeat(32),
                    cleanup_id: "66".repeat(32),
                },
            ),
        },
        key_id: "response-key".into(),
        signature: "77".repeat(64),
    };
    let wire = serde_json::to_vec(&response).expect("response wire");
    assert_eq!(
        decode_authority_response_strict(&wire).expect("closed cleanup response"),
        response
    );
}

#[test]
fn cleanup_rejects_zero_revision_and_open_fields() {
    let mut request = request();
    let AuthorityCommand::AcknowledgePendingCancellation(command) = &mut request.command else {
        unreachable!()
    };
    command.cleanup_completed_revision = 0;
    let wire = serde_json::to_vec(&request).expect("cleanup request wire");
    assert!(decode_authority_request_strict(&wire).is_err());
    let mut open = serde_json::to_value(request).expect("json");
    open["command"]["unknown"] = true.into();
    assert!(serde_json::from_value::<AuthorityRequestV1>(open).is_err());
}
