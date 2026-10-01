"""Closed schema loading and deterministic record validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


CONTRACT_NAMES = (
    "subject-link",
    "service-account",
    "authenticator-projection",
    "registered-device",
    "user-session",
    "identity-provider-connection",
    "step-up-evidence",
    "account-recovery",
    "owner-recovery-profile",
    "revocation-event",
)
_ROOT = Path(__file__).resolve().parents[2]
_MAXIMUM_BYTES = 256 * 1024


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_json(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"contract input must be a regular file: {path.name}")
    if metadata.st_size > _MAXIMUM_BYTES:
        raise ValueError(f"contract input exceeds {_MAXIMUM_BYTES} bytes: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError(f"contract input must be an object: {path.name}")
    return value


def _path(directory: str, name: str, suffix: str) -> Path:
    if name not in CONTRACT_NAMES:
        raise ValueError(f"unknown identity contract: {name}")
    return _ROOT / directory / f"{name}-v1.{suffix}.json"


def load_contract(name: str) -> dict[str, Any]:
    return _read_json(_path("schemas", name, "schema"))


def load_example(name: str) -> dict[str, Any]:
    return _read_json(_path("examples", name, "example"))


def record_digest(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "digest"}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _temporal_errors(name: str, record: dict[str, Any]) -> list[str]:
    messages = []
    if record["updated_at"] < record["created_at"]:
        messages.append("updated_at: precedes created_at")
    immutable = {"step-up-evidence", "revocation-event"}
    if name in immutable and record["updated_at"] != record["created_at"]:
        messages.append("updated_at: immutable evidence must equal created_at")
    starts = {
        "user-session": "authenticated_at",
        "step-up-evidence": "authenticated_at",
        "account-recovery": "initiated_at",
    }
    start = starts.get(name)
    if start and record["expires_at"] <= record[start]:
        messages.append(f"expires_at: must be later than {start}")
    return messages


def validate_record(name: str, record: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(load_contract(name), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(record), key=lambda error: list(error.absolute_path))
    messages = [f"{'.'.join(map(str, error.absolute_path)) or '$'}: {error.message}" for error in errors]
    if not errors:
        messages.extend(_temporal_errors(name, record))
        if name == "owner-recovery-profile":
            public_key = bytes.fromhex(record["public_key_hex"])
            fingerprint = hashlib.sha256(public_key).hexdigest()
            if record["key_fingerprint"] != fingerprint:
                messages.append("key_fingerprint: does not match public key")
            if not record["authority_id"].endswith(fingerprint):
                messages.append("authority_id: does not bind the root fingerprint")
            if not record["key_id"].endswith(fingerprint):
                messages.append("key_id: does not bind the root fingerprint")
        if record.get("digest") != record_digest(record):
            messages.append("digest: does not match canonical record payload")
    return messages
