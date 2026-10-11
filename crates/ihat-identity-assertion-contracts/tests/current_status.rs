mod current_status_support;

use current_status_support::{Key, NOW, STATUS_AUDIENCE, STATUS_ISSUER, assertion, sign, status};
use ihat_identity_assertion_contracts::{
    current_status_matches_assertion, decode_current_status_strict, verify_current_status_at,
};

#[test]
fn current_status_is_closed_signed_short_lived_and_assertion_bound() {
    let assertion = assertion("device:source", 2, "assertion-nonce:01");
    let (status, key) = sign(status(&assertion));
    let decoded = decode_current_status_strict(&serde_json::to_vec(&status).expect("status wire"))
        .expect("closed status");
    verify_current_status_at(
        &decoded,
        &Key("status-key:1", key),
        STATUS_ISSUER,
        STATUS_AUDIENCE,
        NOW,
    )
    .expect("current status");
    assert!(current_status_matches_assertion(&decoded, &assertion));
}

#[test]
fn re_signed_new_epoch_is_valid_status_but_not_current_for_old_assertion() {
    let assertion = assertion("device:source", 2, "assertion-nonce:01");
    let mut changed = status(&assertion);
    changed.revocation_epochs.device += 1;
    let (changed, key) = sign(changed);
    verify_current_status_at(
        &changed,
        &Key("status-key:1", key),
        STATUS_ISSUER,
        STATUS_AUDIENCE,
        NOW,
    )
    .expect("cryptographically valid new status");
    assert!(!current_status_matches_assertion(&changed, &assertion));
}

#[test]
fn same_device_and_epochs_with_another_session_ref_do_not_match() {
    let assertion = assertion("device:source", 2, "assertion-nonce:01");
    let mut changed = status(&assertion);
    changed.session_ref = "sref_service_crowsi_02".into();
    let (changed, key) = sign(changed);
    verify_current_status_at(
        &changed,
        &Key("status-key:1", key),
        STATUS_ISSUER,
        STATUS_AUDIENCE,
        NOW,
    )
    .expect("cryptographically valid other session");
    assert!(!current_status_matches_assertion(&changed, &assertion));
}
