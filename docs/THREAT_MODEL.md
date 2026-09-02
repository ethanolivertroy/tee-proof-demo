# Threat model

This document bounds what the demo claims. It covers both reviewed routes. Where the routes differ, each route has its own line.

## Security goal

The browser holds the synthetic prompt in plaintext until it has verified fresh evidence against the compiled policy in `src/lib/policy.ts`. The evidence must bind all of these:

Both routes:

- an authentic Intel TDX quote, verified against Intel collateral in a browser worker;
- a TCB status of `UpToDate`;
- a debug-disabled TDX state;
- the approved measurement profile (MRTD, RTMR0 to RTMR3, and the route-specific configuration measurement);
- a browser-generated 32-byte nonce inside the quote report data;
- the exact public keys the browser will encrypt to and authenticate with;
- a local evidence lifetime of five minutes or less.

NEAR AI Cloud route:

- the approved Compose manifest and OS image hashes;
- the model encryption and signing key, bound to the nonce;
- the expected NVIDIA architecture and device count;
- signed, fresh NVIDIA device and overall verdicts with secure boot, debug disabled, valid measurements, and an overall pass.

Phala Cloud route:

- the replayed TDX event log and the measured `app_compose`;
- the measured source repository and commit;
- dstack KMS custody of the gateway keys, under the pinned KMS root key;
- the `workload_keyset_digest` of the served keyset, and a keyset `not_after` in the future;
- the E2EE key, receipt-signing key, and TLS SPKI for `inference.phala.com` from that keyset.

## The relay

The Cloudflare Worker rejects every `/api` route unless the request carries the owner token. It then accepts only the fixed encrypted request shape, adds the deployer's provider key, and forwards the ciphertext to one of three fixed origins: the NEAR endpoint, the Phala endpoint, or the NVIDIA attestation service. It removes the owner token before forwarding, streams request bodies with a byte cap, and logs no request or response bodies.

The Worker is not a hardware TEE. It sees ciphertext, request metadata, and provider responses. A malicious Worker cannot read the prompt or completion because both are encrypted to keys the browser verified against the quote.

## Protected from

- A relay that attempts to read prompt or completion plaintext.
- A request that selects an arbitrary model, provider, origin, or credential.
- Stale, replayed, wrong-nonce, debug-mode, wrong-measurement, or wrong-device evidence.
- A gateway or model whose keys are not the attested keys.
- A NEAR completion signed by a key other than the fresh attested key, or whose signed text does not match the exact encrypted request and response bytes.
- A Phala completion whose receipt is not signed by the attested receipt key, or whose receipt does not bind the request hash, the encrypted wire response hash, the model, the endpoint, and the verified keyset digest.
- Anonymous use of the deployer's Worker to relay traffic to the providers or to NVIDIA.
- Clickjacking or framing of the owner gate, on every path the app is served from.

## Not protected from

- Browser, extension, or endpoint compromise.
- Availability failures or provider refusal to serve.
- Traffic analysis, timing, request size, IP address, or billing metadata. The browser connects directly to NVIDIA for its JWKS and to Intel and Phala PCCS endpoints for quote collateral, so those parties see the visitor's IP address and timing.
- A malicious workload that nevertheless matches an incorrectly approved policy.
- Provider or project administrators changing routing or deleting infrastructure.
- Exact model-weight substitution when the measured workload does not pin immutable weight bytes.
- On the Phala route, the browser verifies the gateway. Evidence about the upstream inference node arrives inside the signed receipt after the completion, so the browser trusts the attested gateway to have enforced its own upstream policy.
- Owner-token disclosure. The gate is a shared secret, not identity-aware SSO, rate limiting, or a hard provider spending cap.

## Data boundary

Use synthetic prompts only. The template has no persistence and its Worker logs no request or response bodies, but that is not a compliance or retention guarantee for every dependency or provider involved.

## Claim ladder

- **Verified environment.** The browser verified current TDX evidence against the compiled policy. On the NEAR route it also verified fresh NVIDIA evidence for eight GPUs. On the Phala route it also verified the dstack source, Compose, KMS, and keyset chain.
- **Encrypted request.** The browser encrypted the prompt to the attested key before network release.
- **Verified completion.** The browser authenticated the exact encrypted request and response bytes with the attested signing or receipt key, then decrypted the completion. The decrypted text is what those authenticated bytes decrypt to under the browser's own key.
- **Not claimed.** Production secret release, regulated-data authorization, hidden metadata, direct browser verification of the Phala upstream node, or safety of arbitrary code execution.
