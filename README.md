# ihat-identity-contracts

Exchange account, device and session information through strict identity contracts.

## What you can do

- Validate closed identity and revocation projections.
- Keep secret values out of display and exchange objects.

## Current scope

Consumers supply their identity authority, storage and trust integrations.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## Examples and interface details

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

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Examples](examples) · [Schemas](schemas) · [Detailed documentation](docs) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
