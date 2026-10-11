use serde::{Deserialize, Serialize};

use crate::{
    DeviceMetadata, DeviceRevocationMetadata, FreshUvRequestOptions, FreshUvV1,
    IdentityEvidenceMetadata, PendingCancellationAcknowledgedMetadata,
    PendingRevocationCancelledMetadata, RevocationApprovalMetadata, RevocationCeremonyMetadata,
    RevocationMetadata, SecretFreeProjection, ServiceMetadata, SessionMetadata,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorityResult {
    IdentityLinked {
        subject_epoch: u64,
    },
    ServiceAccountCreated(ServiceMetadata),
    DeviceRegistered(DeviceMetadata),
    DeviceKeyRotated(DeviceMetadata),
    DeviceRecovered(DeviceMetadata),
    SessionOpened(SessionMetadata),
    SessionAuthorized {
        authorized: bool,
    },
    Revocation(RevocationMetadata),
    DeviceRevocation(DeviceRevocationMetadata),
    RevocationBegun(RevocationCeremonyMetadata),
    RevocationApproved(RevocationApprovalMetadata),
    PendingRevocationCancelled(PendingRevocationCancelledMetadata),
    PendingCancellationAcknowledged(PendingCancellationAcknowledgedMetadata),
    ServiceAccountClosed {
        service_id: String,
        service_epoch: u64,
    },
    IdentityEvidence(IdentityEvidenceMetadata),
    FreshUvBegun(FreshUvRequestOptions),
    FreshUvFinished {
        document: FreshUvV1,
    },
    Reconciled {
        original_command_digest: String,
        result: Box<AuthorityResult>,
    },
    SecretFreeProjection(SecretFreeProjection),
}
