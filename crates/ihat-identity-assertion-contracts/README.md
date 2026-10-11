# ihat-identity-assertion-contracts

Verify a short-lived device identity assertion against an explicitly pinned issuer and audience.

## What you can do

- Validate pairwise subject, device and revocation context.
- Enforce bounded validity and privileged-consumer requirements.

## Current scope

The consumer supplies trusted time and keys. An assertion is not a credential export or permission grant.

This is the iHAT device identity and authority wire contract, not a general-purpose identity provider. It includes iHAT account, device, session, recovery and revocation schemas. Consumers provide trusted time and pinned keys; no account database or credential export is included.

## Package availability and verification

This is a reviewed distribution candidate; enabling crates.io in the manifest does not mean the version has been published. Verify registry availability before using the exact version. Rust 1.97 or newer is required. All dependencies must resolve from crates.io.

```sh
cargo test --locked --all-targets
cargo test --locked --doc
cargo package --locked
```

Conformance fixtures contain checked synthetic contexts and deterministic sequential-byte signing seeds. These public test-only values must never be used for operational signing or authentication.

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schema) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
