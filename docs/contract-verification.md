# Contract verification profile

## Structural verification

Consumers select a schema by an exact allowlisted URI; they do not fetch `$id` over the network.
Every object is closed with `additionalProperties: false`. Missing fields, unknown schema revisions,
invalid formats and unbounded values fail before state mutation. Input is decoded once as JSON; duplicate
keys must be rejected by the transport decoder before schema validation.

All timestamps use UTC with exactly millisecond precision (`YYYY-MM-DDTHH:mm:ss.sssZ`). IDs are opaque,
type-prefixed values. Callers must not derive meaning, email or tenancy from an ID string.

`digest` is calculated as `sha256:` plus lowercase SHA-256 of UTF-8 canonical JSON after removing the
top-level `digest`: object keys sorted lexicographically, no insignificant whitespace, Unicode emitted
without ASCII escaping, integers only for numeric fields. Future schemas must define a new version before
introducing non-integer JSON numbers or a different canonicalization profile.

## Contextual verification

JSON Schema cannot establish trust. A consumer also verifies:

1. issuer equals the configured issuer byte-for-byte;
2. audience equals the current Service, not merely a member of a broad list;
3. signature/JWKS and Provider evidence were validated by the owning adapter;
4. `authenticated_at` is not in the future beyond the allowed trusted-clock skew;
5. `expires_at` is strictly later than both authentication time and current trusted time;
6. revocation epoch is current and the referenced Account/Device/Session remains active;
7. operation, Device, Workload and proof-key bindings equal the pending request;
8. step-up evidence ID and nonce digest are consumed atomically only after all checks pass.

The included Python verifier demonstrates issuer, audience, temporal, assurance, operation and in-process
replay behavior for contract tests. `AcceptancePolicy.provider_evidence_verified` defaults to false and
must be set only after the owning adapter verifies signature/JWKS and Provider evidence. The same minimum
assurance check applies to ordinary sessions and step-up evidence. Its in-memory ledger is not a production
replay store. Production must use durable atomic state that survives restart and concurrent consumers.

## Assurance mapping

`totp` and `authenticator-push` map only to `baseline`. `passkey` and `fido2-security-key` may map to
`phishing-resistant` after RP ID/origin/user-verification checks. `hardware-bound` additionally needs an
approved attestation policy; naming a method or Device as hardware-bound is not sufficient evidence.

## Change rules

- Additive fields still require a new contract version because objects are closed.
- Existing v1 schemas are immutable after release except documentation-only corrections.
- Consumers maintain an explicit accepted-version allowlist and fail closed on v2 until upgraded.
- Migrations write a new record and preserve provenance; they do not reinterpret an old digest.
- Example fixtures are synthetic and never serve as issuer, key, account or production-readiness evidence.
