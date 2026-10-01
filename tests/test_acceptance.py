import copy
import unittest
from datetime import datetime, timezone

from ihat_identity_contracts import AcceptancePolicy, ReplayLedger, VerificationError
from ihat_identity_contracts import consume_step_up, load_example, record_digest, verify_session


NOW = datetime(2026, 8, 3, 1, 0, 30, tzinfo=timezone.utc)
POLICY = AcceptancePolicy(
    issuer="https://id.ihat.online",
    audience="nerp",
    operation_digest="sha256:" + "6" * 64,
    service_account_id="service-account/nerp-001",
    pairwise_subject="pairwise_nerp_subject_001",
    device_id="device/windows-001",
    workload_id="local-workload/nerp-bff",
    actor_id="service/nerp-bff",
    proof_key_thumbprint="sha256:" + "1" * 64,
    revocation_epoch=0,
    provider_evidence_verified=True,
)


def changed(record, field, value):
    record[field] = value
    record["digest"] = record_digest(record)
    return record


class AcceptanceTests(unittest.TestCase):
    def test_unverified_provider_evidence_is_never_accepted(self):
        unverified = AcceptancePolicy(
            issuer=POLICY.issuer,
            audience=POLICY.audience,
            service_account_id=POLICY.service_account_id,
            device_id=POLICY.device_id,
        )
        with self.assertRaisesRegex(VerificationError, "provider evidence"):
            verify_session(load_example("user-session"), unverified, NOW)

    def test_expected_session_is_accepted(self):
        verify_session(load_example("user-session"), POLICY, NOW)

    def test_session_must_meet_the_policy_assurance(self):
        session = changed(load_example("user-session"), "assurance", "baseline")
        session = changed(session, "authentication_methods", ["totp"])
        with self.assertRaisesRegex(VerificationError, "assurance"):
            verify_session(session, POLICY, NOW)

    def test_session_cannot_cross_account_device_or_revocation_epoch(self):
        for field, value in [
            ("service_account_id", "service-account/nerp-002"),
            ("device_id", "device/other-001"),
            ("revocation_epoch", 1),
        ]:
            session = changed(load_example("user-session"), field, value)
            with self.assertRaisesRegex(VerificationError, field, msg=field):
                verify_session(session, POLICY, NOW)

    def test_wrong_issuer_audience_and_expiry_are_rejected(self):
        for field, value, expected in [
            ("issuer", "https://lookalike.example", "issuer"),
            ("audience", "hibee", "audience"),
            ("expires_at", "2026-08-03T01:00:29.000Z", "expired"),
        ]:
            session = changed(load_example("user-session"), field, value)
            with self.assertRaisesRegex(VerificationError, expected, msg=field):
                verify_session(session, POLICY, NOW)

    def test_step_up_is_exactly_bound_and_one_use(self):
        evidence = load_example("step-up-evidence")
        ledger = ReplayLedger()
        consume_step_up(evidence, POLICY, NOW, ledger)
        with self.assertRaisesRegex(VerificationError, "replay"):
            consume_step_up(evidence, POLICY, NOW, ledger)

        same_nonce = changed(load_example("step-up-evidence"), "id", "step-up/other-id-001")
        with self.assertRaisesRegex(VerificationError, "replay"):
            consume_step_up(same_nonce, POLICY, NOW, ledger)

    def test_step_up_cannot_cross_operation_or_audience(self):
        evidence = load_example("step-up-evidence")
        for field, value in [
            ("operation_digest", "sha256:" + "7" * 64),
            ("audience", "hibee"),
            ("issuer", "https://lookalike.example"),
        ]:
            candidate = changed(copy.deepcopy(evidence), field, value)
            with self.assertRaisesRegex(VerificationError, field, msg=field):
                consume_step_up(candidate, POLICY, NOW, ReplayLedger())

    def test_step_up_cannot_cross_identity_device_workload_or_proof_key(self):
        evidence = load_example("step-up-evidence")
        for field, value in [
            ("service_account_id", "service-account/nerp-002"),
            ("pairwise_subject", "pairwise_nerp_subject_002"),
            ("device_id", "device/other-001"),
            ("workload_id", "local-workload/other-bff"),
            ("actor_id", "service/other-bff"),
            ("proof_key_thumbprint", "sha256:" + "5" * 64),
            ("revocation_epoch", 1),
        ]:
            candidate = changed(copy.deepcopy(evidence), field, value)
            with self.assertRaisesRegex(VerificationError, field, msg=field):
                consume_step_up(candidate, POLICY, NOW, ReplayLedger())

    def test_expired_or_baseline_step_up_is_rejected(self):
        for field, value in [
            ("expires_at", "2026-08-03T01:00:29.000Z"),
            ("assurance", "baseline"),
        ]:
            evidence = changed(load_example("step-up-evidence"), field, value)
            expected = "expired" if field == "expires_at" else "assurance"
            with self.assertRaisesRegex(VerificationError, expected, msg=field):
                consume_step_up(evidence, POLICY, NOW, ReplayLedger())


if __name__ == "__main__":
    unittest.main()
