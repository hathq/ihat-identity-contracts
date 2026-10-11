# Using ihat-identity-assertion-contracts

Verify a short-lived device identity assertion against an explicitly pinned issuer and audience.

## Before you start

The consumer supplies trusted time and keys. An assertion is not a credential export or permission grant.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate pairwise subject, device and revocation context.
- Enforce bounded validity and privileged-consumer requirements.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
