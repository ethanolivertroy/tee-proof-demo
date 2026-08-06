# Threat model

## Security goal

A browser with the checked-in policy should withhold prompt plaintext until it verifies fresh evidence binding:

- an authentic Intel TDX quote;
- debug-disabled TDX state;
- one coherent approved measurement profile;
- the approved Compose manifest and OS image;
- a browser-generated nonce;
- the exact model encryption/signing key;
- the expected NVIDIA architecture and device count;
- signed, fresh NVIDIA device and overall verdicts;
- secure boot, debug-disabled GPU state, valid measurements, and an overall pass.

The Cloudflare Worker then accepts only the fixed encrypted request shape, adds the deployer's provider key, and forwards the exact ciphertext to one fixed origin.

## Protected from

- A relay that attempts to read prompt or completion plaintext.
- A request that selects an arbitrary model, provider, origin, or credential.
- Stale, replayed, wrong-nonce, debug, wrong-measurement, or wrong-device evidence.
- A completion signed by a key other than the fresh attested key.
- A response whose exact encrypted bytes do not match the signed receipt.

## Not protected from

- Browser, extension, or endpoint compromise.
- Availability failures or provider refusal to serve.
- Traffic analysis, timing, request size, IP address, or billing metadata.
- A malicious workload that nevertheless matches an incorrectly approved policy.
- Provider/project administrators changing routing or deleting infrastructure.
- Credential abuse against a publicly shared Worker without additional access controls.
- Exact model-weight substitution when the measured workload does not pin immutable weight bytes.

## Data boundary

Use synthetic prompts only. The template intentionally has no persistence and its Worker logs no request or response bodies, but that is not a compliance or retention guarantee for every dependency or provider involved.

## Claim ladder

- **Verified environment:** browser verified current TDX and NVIDIA evidence against the checked-in policy.
- **Encrypted request:** browser encrypted the prompt to the attested model key before network release.
- **Verified completion:** browser authenticated the exact encrypted request and response, then decrypted the completion.
- **Not claimed:** production secret release, regulated-data authorization, hidden metadata, or safety of arbitrary code execution.
