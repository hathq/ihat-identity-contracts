"""Context checks that JSON Schema alone cannot express."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from .contracts import validate_record


class VerificationError(ValueError):
    """The record cannot be trusted for the requested context."""


@dataclass(frozen=True)
class AcceptancePolicy:
    issuer: str
    audience: str
    operation_digest: str | None = None
    service_account_id: str | None = None
    pairwise_subject: str | None = None
    device_id: str | None = None
    workload_id: str | None = None
    actor_id: str | None = None
    proof_key_thumbprint: str | None = None
    revocation_epoch: int | None = None
    provider_evidence_verified: bool = False
    minimum_assurance: str = "phishing-resistant"
    maximum_future_skew_seconds: int = 30


class ReplayLedger:
    """Thread-safe demonstration only; production requires durable atomic state."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = Lock()

    def consume(self, *keys: str) -> bool:
        with self._lock:
            if self._consumed.intersection(keys):
                return False
            self._consumed.update(keys)
            return True


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError) as error:
        raise VerificationError("invalid timestamp") from error
    return parsed.replace(tzinfo=timezone.utc)


def _validate(name: str, record: dict[str, Any]) -> None:
    errors = validate_record(name, record)
    if errors:
        raise VerificationError("contract validation failed: " + "; ".join(errors))


def _verify_context(record: dict[str, Any], policy: AcceptancePolicy, now: datetime) -> None:
    if policy.provider_evidence_verified is not True:
        raise VerificationError("provider evidence was not independently verified")
    if now.tzinfo is None or now.utcoffset() is None:
        raise VerificationError("trusted time must include a timezone")
    if record["issuer"] != policy.issuer:
        raise VerificationError("issuer mismatch")
    if record["audience"] != policy.audience:
        raise VerificationError("audience mismatch")
    authenticated = _timestamp(record["authenticated_at"])
    expires = _timestamp(record["expires_at"])
    maximum_auth_time = now + timedelta(seconds=policy.maximum_future_skew_seconds)
    if authenticated > maximum_auth_time:
        raise VerificationError("authentication time is in the future")
    if expires <= authenticated or expires <= now:
        raise VerificationError("evidence expired")


def verify_session(record: dict[str, Any], policy: AcceptancePolicy, now: datetime) -> None:
    _validate("user-session", record)
    _verify_context(record, policy, now)
    if record["status"] != "active":
        raise VerificationError("session is not active")
    expected = {
        "service_account_id": policy.service_account_id,
        "device_id": policy.device_id,
        "revocation_epoch": policy.revocation_epoch,
    }
    _verify_bindings(record, expected)
    _verify_assurance(record["assurance"], policy.minimum_assurance)


def _verify_bindings(record: dict[str, Any], expected: dict[str, Any]) -> None:
    for field, value in expected.items():
        if value is not None and record[field] != value:
            raise VerificationError(f"{field} mismatch")


def _verify_assurance(actual: str, minimum: str) -> None:
    levels = {"baseline": 0, "phishing-resistant": 1, "hardware-bound": 2}
    if minimum not in levels:
        raise VerificationError("acceptance policy has an invalid assurance level")
    if levels[actual] < levels[minimum]:
        raise VerificationError("insufficient assurance")


def consume_step_up(
    record: dict[str, Any], policy: AcceptancePolicy, now: datetime, ledger: ReplayLedger
) -> None:
    _validate("step-up-evidence", record)
    _verify_context(record, policy, now)
    expected = {
        "operation_digest": policy.operation_digest,
        "service_account_id": policy.service_account_id,
        "pairwise_subject": policy.pairwise_subject,
        "device_id": policy.device_id,
        "workload_id": policy.workload_id,
        "actor_id": policy.actor_id,
        "proof_key_thumbprint": policy.proof_key_thumbprint,
        "revocation_epoch": policy.revocation_epoch,
    }
    _verify_bindings(record, expected)
    _verify_assurance(record["assurance"], policy.minimum_assurance)
    keys = (f"evidence:{record['id']}", f"nonce:{record['nonce_digest']}")
    if not ledger.consume(*keys):
        raise VerificationError("step-up replay")
