# iHAT Identity Contracts

Implementation-independent, closed v1 contracts for exchanging authentication, service-account, device, session, step-up, recovery, and revocation projections. Consumers implement their own authority and storage integrations through these contracts.

## Contracts

- `SubjectLink`: explicitly authenticated external-provider link and RP-specific pairwise subject.
- `ServiceAccount`: service-owned account and role.
- `AuthenticatorProjection`: display projection with secret values excluded.
- `RegisteredDevice`: registered device with public-key thumbprint and broker reference.
- `UserSession`: service session represented by a handle digest.
- `IdentityProviderConnection`: fixed issuer, client, redirect, and scope allowlists.
- `StepUpEvidence`: short-lived evidence bound to subject, device, workload, and operation.
- `OwnerRecoveryProfile`: public descriptor and fixed cryptographic profile for an owner-local 24-word primary recovery root.
- `AccountRecovery`: a ceremony using two or more independent authorities, including recovery-root and new-device identity checks.
- `RevocationEvent`: append-only event with epoch and sequence.

Schema URIs are `ihat://identity/<contract>/v1`. Consumers allowlist them and resolve schemas locally. All objects reject unknown fields.

## Verification

Use Python 3.11 or later and the pinned validator in `requirements-test.txt`.

```bash
make check
```

The gate validates nine schemas, valid fixtures, unknown fields, versions, IDs, timestamps, digests, weak-authenticator promotion, issuer/audience/expiry, operation binding, and replay. Synthetic examples do not establish authentication, a connected service, or production readiness.

## Documents

- `docs/adr/0001-identity-authentication-boundaries.md`: authority and database boundaries.
- `docs/threat-model.md`: attack surface, controls, and required negative tests.
- `docs/data-classification.md`: classification, storage, retention, and deletion responsibilities.
- `docs/contract-verification.md`: digest and context verification rules.
