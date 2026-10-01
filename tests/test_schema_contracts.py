import copy
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from ihat_identity_contracts import CONTRACT_NAMES, load_contract, load_example
from ihat_identity_contracts import record_digest, validate_record


COMMON_FIELDS = {"schema", "id", "revision", "created_at", "updated_at", "digest"}
FORBIDDEN_PROPERTIES = {
    "access_token",
    "email",
    "id_token",
    "otp_seed",
    "private_key",
    "raw_assertion",
    "refresh_token",
    "upn",
}


def object_schemas(node):
    if isinstance(node, dict):
        if node.get("type") == "object":
            yield node
        for value in node.values():
            yield from object_schemas(value)
    elif isinstance(node, list):
        for value in node:
            yield from object_schemas(value)


def property_names(node):
    if isinstance(node, dict):
        yield from node.get("properties", {}).keys()
        for value in node.values():
            yield from property_names(value)
    elif isinstance(node, list):
        for value in node:
            yield from property_names(value)


class SchemaContractTests(unittest.TestCase):
    def test_catalog_contains_exactly_the_ten_v1_contracts(self):
        self.assertEqual(len(CONTRACT_NAMES), 10)
        self.assertEqual(len(set(CONTRACT_NAMES)), 10)
        expected = {f"{name}-v1.schema.json" for name in CONTRACT_NAMES}
        actual = {path.name for path in (Path(__file__).parents[1] / "schemas").glob("*.json")}
        self.assertEqual(actual, expected)

    def test_schemas_are_valid_closed_draft_2020_12_documents(self):
        for name in CONTRACT_NAMES:
            schema = load_contract(name)
            Draft202012Validator.check_schema(schema)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(schema["$id"], f"ihat://identity/{name}/v1")
            self.assertEqual(schema["properties"]["schema"]["const"], schema["$id"])
            self.assertTrue(COMMON_FIELDS.issubset(schema["required"]))
            for object_schema in object_schemas(schema):
                self.assertIs(object_schema.get("additionalProperties"), False, name)

    def test_schemas_never_define_raw_identifiers_or_credentials(self):
        for name in CONTRACT_NAMES:
            names = set(property_names(load_contract(name)))
            self.assertFalse(names & FORBIDDEN_PROPERTIES, name)

    def test_examples_are_accepted_and_unknown_fields_are_rejected(self):
        for name in CONTRACT_NAMES:
            example = load_example(name)
            self.assertEqual(validate_record(name, example), [], name)
            example["ambient_authority"] = True
            self.assertTrue(validate_record(name, example), name)

    def test_payload_mutation_without_digest_update_is_rejected(self):
        account = load_example("service-account")
        account["roles"] = ["administrator"]
        self.assertIn("digest: does not match canonical record payload", validate_record("service-account", account))

    def test_version_id_timestamp_and_digest_are_fail_closed(self):
        for name in CONTRACT_NAMES:
            valid = load_example(name)
            mutations = [
                ("schema", "ihat://identity/future/v9"),
                ("id", "../shared-account"),
                ("revision", 0),
                ("created_at", "2026-08-03 00:00:00"),
                ("digest", "sha256:not-a-digest"),
            ]
            for field, invalid in mutations:
                candidate = copy.deepcopy(valid)
                candidate[field] = invalid
                self.assertTrue(validate_record(name, candidate), f"{name}.{field}")

    def test_email_cannot_drive_subject_linking(self):
        link = load_example("subject-link")
        link["email"] = "same-address@example.test"
        self.assertTrue(validate_record("subject-link", link))

    def test_weak_authenticators_cannot_claim_phishing_resistance(self):
        authenticator = load_example("authenticator-projection")
        authenticator["kind"] = "totp"
        authenticator["assurance"] = "phishing-resistant"
        self.assertTrue(validate_record("authenticator-projection", authenticator))

    def test_provider_connection_forbids_automatic_email_linking(self):
        connection = load_example("identity-provider-connection")
        connection["automatic_email_linking"] = True
        self.assertTrue(validate_record("identity-provider-connection", connection))

    def test_provider_connection_rejects_wildcard_redirects_and_issuer_queries(self):
        connection = load_example("identity-provider-connection")
        for field, value in [
            ("redirect_uris", ["https://*.ihat.online/auth/callback"]),
            ("issuer", "https://id.ihat.online?tenant=other"),
        ]:
            candidate = copy.deepcopy(connection)
            candidate[field] = value
            self.assertTrue(validate_record("identity-provider-connection", candidate), field)

    def test_recovery_requires_independent_authorities(self):
        recovery = load_example("account-recovery")
        recovery["authority_references"] = recovery["authority_references"][:1]
        self.assertTrue(validate_record("account-recovery", recovery))

    def test_owner_recovery_profile_freezes_crypto_and_binds_public_root(self):
        profile = load_example("owner-recovery-profile")
        self.assertEqual(validate_record("owner-recovery-profile", profile), [])
        for field, value in [
            ("seed_kdf_rounds", 1),
            ("mnemonic_word_count", 12),
            ("key_fingerprint", "00" * 32),
        ]:
            candidate = copy.deepcopy(profile)
            candidate[field] = value
            candidate["digest"] = record_digest(candidate)
            self.assertTrue(validate_record("owner-recovery-profile", candidate), field)

    def test_revocation_target_type_and_identifier_must_match(self):
        event = load_example("revocation-event")
        event["aggregate_type"] = "device"
        self.assertTrue(validate_record("revocation-event", event))

    def test_immutable_evidence_cannot_claim_an_update(self):
        event = load_example("revocation-event")
        event["updated_at"] = "2026-08-03T01:00:21.000Z"
        event["digest"] = record_digest(event)
        self.assertIn(
            "updated_at: immutable evidence must equal created_at",
            validate_record("revocation-event", event),
        )

    def test_hardware_bound_step_up_requires_a_security_key(self):
        evidence = load_example("step-up-evidence")
        evidence["assurance"] = "hardware-bound"
        evidence["authentication_methods"] = ["passkey"]
        self.assertTrue(validate_record("step-up-evidence", evidence))


if __name__ == "__main__":
    unittest.main()
