# ihat-identity-contracts interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

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

## Documents

- `docs/adr/0001-identity-authentication-boundaries.md`: authority and database boundaries.
- `docs/threat-model.md`: attack surface, controls, and required negative tests.
- `docs/data-classification.md`: classification, storage, retention, and deletion responsibilities.
- `docs/contract-verification.md`: digest and context verification rules.
