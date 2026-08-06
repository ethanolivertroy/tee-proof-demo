# Security policy

## Supported version

Only the current `main` branch is supported during the proof-of-concept phase.

## Reporting a vulnerability

Do not open a public issue for a suspected secret exposure, attestation bypass, plaintext leak, origin-selection flaw, cryptographic weakness, or credential-handling problem. Use GitHub private vulnerability reporting for this repository.

Include the affected commit, reproduction steps, expected denial, observed behavior, and whether any real credential or prompt data may have been exposed. Do not include live secrets in the report.

## Dependency note

`@phala/dcap-qvl` currently pulls `elliptic@6.6.1`, which has the low-severity signing advisory [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84) and no patched release. This application invokes that dependency only to verify Intel collateral signatures; it does not generate ECDSA signatures or hold an ECDSA signing key. CI fails on moderate-or-higher production advisories, and Dependabot monitors the chain for a compatible fix.

## Operational boundary

A template deployment creates a publicly reachable `workers.dev` hostname. The built-in `DEMO_ACCESS_TOKEN` gate rejects every provider-billed chat, signature, receipt, and session route unless the caller presents the matching shared secret; the token is removed before provider forwarding. Static assets and attestation endpoints remain public.

This shared-secret gate is not identity-aware authorization, rate limiting, or a hard provider spending cap. Operators should also enable [Cloudflare Access for the Worker](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/#manage-access-to-workersdev), restrict allowed identities, validate their Access configuration, and configure provider-side budget controls before sharing the URL. The project is not a production data-handling authorization.
