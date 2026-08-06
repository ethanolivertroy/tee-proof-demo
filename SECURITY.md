# Security policy

## Supported version

Only the current `main` branch is supported during the proof-of-concept phase.

## Reporting a vulnerability

Do not open a public issue for a suspected secret exposure, attestation bypass, plaintext leak, origin-selection flaw, cryptographic weakness, or credential-handling problem. Use GitHub private vulnerability reporting for this repository.

Include the affected commit, reproduction steps, expected denial, observed behavior, and whether any real credential or prompt data may have been exposed. Do not include live secrets in the report.

## Dependency note

`@phala/dcap-qvl` currently pulls `elliptic@6.6.1`, which has the low-severity signing advisory [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84) and no patched release. This application invokes that dependency only to verify Intel collateral signatures; it does not generate ECDSA signatures or hold an ECDSA signing key. CI fails on moderate-or-higher production advisories, and Dependabot monitors the chain for a compatible fix.

## Operational boundary

A template deployment creates a public `workers.dev` endpoint backed by the deployer's provider credential. The repository does not provide authentication, Cloudflare Access, a hard provider spending cap, or a production data-handling authorization. Operators are responsible for adding those controls before sharing their URL.
