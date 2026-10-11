use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ihat_identity_assertion_contracts::{
    AssertionVerifier, CurrentDeviceStatusV1, DeviceIdentityAssertionV1, DevicePostureV1,
    RevocationEpochsV1, canonical_current_status_payload,
};

pub const STATUS_ISSUER: &str = "https://identity.example.test";
pub const STATUS_AUDIENCE: &str = "crowsi://credential-authority/device-management/v1";
pub const NOW: u64 = 1_800_000_011;

pub struct Key(pub &'static str, pub VerifyingKey);

impl AssertionVerifier for Key {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        key_id == self.0 && self.1.verify(payload, &signature).is_ok()
    }
}

pub fn assertion(device: &str, device_epoch: u64, nonce: &str) -> DeviceIdentityAssertionV1 {
    DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: STATUS_ISSUER.into(),
        audience: STATUS_AUDIENCE.into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "psu_pairwise_credential_owner_01".into(),
        device_id: device.into(),
        device_proof_key_ref: format!("device-proof:{device}"),
        session_ref: "sref_service_crowsi_01".into(),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 3,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 7,
            service: 5,
            device: device_epoch,
            session: 9,
        },
        issued_at_epoch_s: NOW - 11,
        expires_at_epoch_s: NOW + 19,
        nonce: nonce.into(),
        key_id: "identity-key:1".into(),
        signature: "assertion-signature-not-used-by-binding".into(),
    }
}

pub fn status(assertion: &DeviceIdentityAssertionV1) -> CurrentDeviceStatusV1 {
    CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: assertion.issuer.clone(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        device_id: assertion.device_id.clone(),
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        session_ref: assertion.session_ref.clone(),
        device_posture: assertion.device_posture.clone(),
        revocation_epochs: assertion.revocation_epochs.clone(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 9,
        nonce: assertion.nonce.clone(),
        key_id: "status-key:1".into(),
        signature: String::new(),
    }
}

pub fn sign(mut value: CurrentDeviceStatusV1) -> (CurrentDeviceStatusV1, VerifyingKey) {
    let signing = SigningKey::from_bytes(&[7; 32]);
    value.signature = hex::encode(
        signing
            .sign(&canonical_current_status_payload(&value))
            .to_bytes(),
    );
    (value, signing.verifying_key())
}
