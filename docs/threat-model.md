# iHAT identity threat model

## Scopeと資産

対象はOIDC login/callback、external account link、Authenticator projection、Service
Account、Device registration、Session、step-up、recovery、revocationである。保護資産は
Subject graph、pairwise subject、Authenticator binding、Device public key、session、
token、recovery authority、revocation epoch、監査Evidenceである。

Raw token、OTP seed、private key、WebAuthn assertionはこのRepositoryのContract外であり、
Credential BrokerまたはIdentity Providerの保護境界から出してはならない。

## Trust boundaries

| 境界 | 信頼しない入力 | 必須検証 |
| --- | --- | --- |
| Browser → Service BFF | cookie、callback、origin | CSRF、state、nonce、exact redirect、session rotation |
| Service → iHAT OIDC | discovery、code、token、JWKS | HTTPS issuer、audience、PKCE、signature、time、key rotation |
| Upstream IdP → iHAT | issuer、external subject、claims | issuer allowlist、nonce、fresh auth、explicit linking |
| Service → Device Agent | device label、challenge response | user-bound enrollment、public-key proof、replay denial |
| Service → Credential Broker | credential reference、lease request | Service/Device/Workload/purpose/audience binding |
| Service → Crowsi | normalized step-up | schema、issuer、audience、expiry、operation、replay ledger |
| Operator → Recovery | authority references、target | dual control、fresh proof、expiry、notification、audit |

## Threats and mandatory tests

| ID | Threat | Control | Required negative test |
| --- | --- | --- | --- |
| T-01 | issuer mix-up/lookalike issuer | exact HTTPS issuer comparison | unconfigured issuer is rejected |
| T-02 | token used by another Service | exact audience and pairwise subject | NERP evidence is rejected by Hibee |
| T-03 | callback interception/CSRF | PKCE S256, state, nonce, one-use code | wrong/reused state, nonce or code fails |
| T-04 | email-based account takeover | dual-authenticated explicit link | equal email cannot create or merge a link |
| T-05 | session fixation/theft | rotate opaque session, HttpOnly cookie, sender binding | pre-login or other-device session fails |
| T-06 | token/secret exfiltration | Broker custody and closed projections | token/seed/private-key fields fail schema |
| T-07 | device impersonation | generated device key and proof thumbprint | other device/proof key fails binding |
| T-08 | weak MFA promoted to strong | closed method-to-assurance mapping | TOTP/push cannot claim phishing resistance |
| T-09 | stale step-up reused | short expiry and atomic replay ledger | expired or second consumption fails |
| T-10 | grant used for another action | exact operation digest | altered operation digest fails |
| T-11 | unknown fields change meaning | closed JSON Schema at every object | additional property fails every contract |
| T-12 | clock rollback | trusted clock watermark in consumer | future auth and expired evidence fail |
| T-13 | stale session after unlink | monotonic revocation epoch/event | lower epoch and revoked session fail |
| T-14 | recovery becomes bypass | the mnemonic root plus an independent fresh device-bound ceremony | one authority/reused ceremony fails |
| T-15 | cross-Service correlation | pairwise subject per audience | pairwise subjects differ across RPs |
| T-16 | compromised admin hides action | append-only revocation/recovery evidence | broken digest/sequence chain fails |

## Abuse cases

An attacker who controls a browser must not receive Provider credentials, choose an arbitrary issuer,
or turn a callback into another Service session. An attacker who copies SQLite must obtain only hashed
session handles, public Device evidence and Broker references. A compromised Service cannot use another
Service's pairwise subject or audience. A compromised phone or TOTP seed cannot authorize a high-risk
operation without the required phishing-resistant factor and exact local sender binding.

Account recovery assumes the daily-use authenticator may be unavailable or compromised. Therefore the
same authenticator, same Provider account, or same operator cannot satisfy both independent authorities.
The owner-held mnemonic is the primary offline authority, never a one-factor reset. Its
public descriptor is registered ahead of loss; the phrase itself never enters iHAT,
Hatter, a HAT, a model, a browser, a log, or default cloud custody. Recovery also
requires fresh user verification from the replacement device and atomically revokes
the affected device and all of its sessions.
Recovery completion must increment revocation state and terminate affected sessions.

## Acceptance and residual risk

Schema success proves only structural conformance. Signature validation, trusted time, revocation
freshness, atomic replay consumption and actual key custody require runtime evidence. Mock or example
records never establish production authentication. External Provider configuration, device attestation,
independent recovery custody and production restore drills remain fail-closed until implemented and
observed by later milestones.
