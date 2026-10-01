# Identity data classification and lifecycle

## Classification model

| Class | Meaning | Examples in this boundary |
| --- | --- | --- |
| `public` | Intentional public interoperability metadata | schema URI, protocol version |
| `internal` | Low-impact operational metadata | Service ID, Provider kind, generic status |
| `internal-confidential` | Linkable account/device metadata | pairwise subject, Device label, last-used time, roles |
| `restricted-sensitive` | Account takeover or correlation impact | Subject link graph, session digest, recovery and step-up evidence |
| `credential-secret` | Direct authentication or signing authority | token, OTP seed, private key, recovery code, raw assertion |

`credential-secret` is forbidden in all ten contracts. A credential reference is opaque, conveys no
authority by itself and is `restricted-sensitive`. Logs and browser projections must apply an explicit
field allowlist; schema acceptance is not permission to expose a field.

## Ownership, storage, retention and deletion

| Contract | Owner / canonical store | Class | Default retention after terminal state | Deletion owner |
| --- | --- | --- | --- | --- |
| `SubjectLink` | iHAT Identity / Identity PostgreSQL | restricted-sensitive | 30 days; retain only non-reversible audit digest afterwards | Identity operator |
| `ServiceAccount` | each Service / its isolated SQLite | internal-confidential | 90 days after closure unless business record policy is longer | Service owner |
| `AuthenticatorProjection` | iHAT; RP copy is regenerable | internal-confidential | 30 days after revoke | Identity operator |
| `RegisteredDevice` | each Service / its isolated SQLite | internal-confidential | 90 days after revoke | Service owner |
| `UserSession` | each Service / session store | restricted-sensitive | 30 days after expiry/revoke | Service owner |
| `IdentityProviderConnection` | iHAT deployment configuration | restricted-sensitive | 90 days after disconnect | Identity operator |
| `StepUpEvidence` | Crowsi replay/audit store | restricted-sensitive | 365 days after expiry | Security operator |
| `AccountRecovery` | iHAT recovery journal | restricted-sensitive | 365 days after completion/cancel | Identity operator |
| `RevocationEvent` | issuing authority append-only journal | restricted-sensitive | aggregate lifetime plus 400 days | Security operator |

These are privacy-preserving defaults, not legal holds. A documented statutory or contractual rule may
extend business-record retention, but must not retain raw credential material. Shorter retention is
allowed when replay and rollback guarantees remain satisfied. Expired replay hashes may be compacted to
non-reversible, key-separated tombstones.

## Required handling

- NERP and Hibee never share a database, encryption key, session namespace or pairwise subject.
- Identity PostgreSQL never becomes a customer data warehouse.
- Browser storage, URLs, process arguments, repository files and general logs contain no token or secret.
- SQLite stores a session-handle digest and Credential Broker reference, never a bearer session/token.
- Device stores expose public-key thumbprints only; the private key remains in the Device/Broker boundary.
- Support exports redact pairwise subjects, Device labels, issuer subjects and credential references.
- Backups inherit the highest contained class and use separate encrypted custody and restore auditing.
- Test fixtures use reserved domains and synthetic opaque identifiers only.

## Erasure and unlink sequence

1. Disable the link/account and increment the relevant revocation epoch.
2. Revoke sessions, Device bindings, Broker credential families and pending step-up evidence.
3. Emit a minimal `RevocationEvent` without email, token, secret or raw Provider claim.
4. Delete direct link fields at the end of the retention window.
5. Keep only the minimum non-reversible digest/epoch needed to reject rollback and replay.
6. Delete Service-local data independently; deletion in NERP must not silently delete Hibee.

An unlink operation is not complete while refresh tokens or active sessions remain usable. Conversely,
removing an upstream Provider does not automatically erase Service business records; that requires an
explicit, separately audited Service request.
