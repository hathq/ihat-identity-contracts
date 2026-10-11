mod current_status_support;

use current_status_support::{Key, NOW, STATUS_AUDIENCE, STATUS_ISSUER, assertion, sign, status};
use ihat_identity_assertion_contracts::{
    current_status_matches_assertion, decode_current_status_strict, verify_current_status_at,
};

#[test]
fn stale_future_wrong_context_and_key_fail_closed() {
    let assertion = assertion("device:a", 2, "nonce:a");
    let (value, key) = sign(status(&assertion));
    let verifier = Key("status-key:1", key);
    for result in [
        verify_current_status_at(&value, &verifier, STATUS_ISSUER, STATUS_AUDIENCE, NOW + 9),
        verify_current_status_at(&value, &verifier, STATUS_ISSUER, STATUS_AUDIENCE, NOW - 2),
        verify_current_status_at(&value, &verifier, "wrong-issuer", STATUS_AUDIENCE, NOW),
        verify_current_status_at(&value, &verifier, STATUS_ISSUER, "wrong-audience", NOW),
        verify_current_status_at(
            &value,
            &Key("wrong-key", verifier.1),
            STATUS_ISSUER,
            STATUS_AUDIENCE,
            NOW,
        ),
    ] {
        assert!(result.is_err());
    }
}

#[test]
fn unknown_trailing_oversized_and_long_lived_status_fail_closed() {
    let assertion = assertion("device:a", 2, "nonce:a");
    let (value, _) = sign(status(&assertion));
    let mut unknown = serde_json::to_value(&value).expect("json");
    unknown["account_id"] = "must-not-cross".into();
    assert!(decode_current_status_strict(&serde_json::to_vec(&unknown).expect("wire")).is_err());
    let mut trailing = serde_json::to_vec(&value).expect("wire");
    trailing.extend_from_slice(b" trailing");
    assert!(decode_current_status_strict(&trailing).is_err());
    assert!(decode_current_status_strict(&vec![b'x'; 16_385]).is_err());
    let mut long = value;
    long.expires_at_epoch_s = long.issued_at_epoch_s + 31;
    assert!(decode_current_status_strict(&serde_json::to_vec(&long).expect("wire")).is_err());
}

#[test]
fn revoked_a_status_never_substitutes_for_current_b_or_old_a_assertion() {
    let old_a = assertion("device:a", 2, "nonce:a");
    let mut revoked_a = status(&old_a);
    revoked_a.revocation_epochs.device = 3;
    let current_b = assertion("device:b", 4, "nonce:b");
    let (revoked_a, _) = sign(revoked_a);
    assert!(!current_status_matches_assertion(&revoked_a, &old_a));
    assert!(!current_status_matches_assertion(&revoked_a, &current_b));
    let mut wrong_nonce = status(&old_a);
    wrong_nonce.nonce = "nonce:substituted".into();
    assert!(!current_status_matches_assertion(&wrong_nonce, &old_a));
}
