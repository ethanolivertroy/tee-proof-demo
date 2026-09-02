# Security policy

## Supported version

Only the current `main` branch is supported during the proof-of-concept phase.

## Reporting a vulnerability

Do not open a public issue for a suspected secret exposure, attestation bypass, plaintext leak, origin-selection flaw, cryptographic weakness, or credential-handling problem. Use GitHub private vulnerability reporting for this repository.

Include the affected commit, reproduction steps, expected denial, observed behavior, and whether any real credential or prompt data may have been exposed. Do not include live secrets in the report.

## Dependency note

`@phala/dcap-qvl` currently pulls `elliptic@6.6.1`, which has the low-severity signing advisory [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84) and no patched release. This application invokes that dependency only to verify Intel collateral signatures; it does not generate ECDSA signatures or hold an ECDSA signing key. CI fails on moderate-or-higher production advisories, and Dependabot monitors the chain for a compatible fix.

## Operational boundary

A template deployment creates a publicly reachable `workers.dev` hostname. The built-in `DEMO_ACCESS_TOKEN` gate rejects every `/api` route, including the attestation and NVIDIA relays, unless the caller presents the matching shared secret; the token is removed before upstream forwarding. Only the static assets remain public. A misconfigured gate (token missing, shorter than 20 characters, or longer than 256 characters) answers 503 on every `/api` route.

The Worker forwards to exactly three fixed origins: the NEAR endpoint, the Phala endpoint, and `nras.attestation.nvidia.com`. The browser also connects directly to NVIDIA for its JWKS and to `pccs.phala.network` and `api.trustedservices.intel.com` for quote collateral. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full boundary.

This shared-secret gate is not identity-aware authorization, rate limiting, or a hard provider spending cap. Add a Cloudflare rate-limiting rule on `/api/*` if the token is shared beyond a small group. Operators should also enable [Cloudflare Access for the Worker](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/#manage-access-to-workersdev), restrict allowed identities, validate their Access configuration, and configure provider-side budget controls before sharing the URL. The project is not a production data-handling authorization.
