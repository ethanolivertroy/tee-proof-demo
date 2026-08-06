# TEE Proof

A minimal, browser-verified confidential inference demo. The browser verifies a fresh Intel TDX quote, NVIDIA confidential-GPU evidence, and a nonce-bound model key before encrypting one synthetic prompt.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ethanolivertroy/tee-proof-demo)

## What the demo proves

```text
Browser verifies TDX + NVIDIA evidence
        ↓
Browser encrypts the prompt to the attested model key
        ↓ ciphertext only
Cloudflare Worker adds your provider credential
        ↓ ciphertext only
Confidential model decrypts, infers, signs, and encrypts
        ↓
Browser verifies the exact completion and decrypts it
```

The Worker has one fixed model and one fixed upstream. It rejects plaintext-shaped messages, arbitrary origins, model substitutions, extra request fields, stale evidence, and malformed GPU-verifier requests.

## Deploy in a few clicks

1. Create a [NEAR AI Cloud API key](https://cloud.near.ai).
2. Select **Deploy to Cloudflare** above.
3. Let Cloudflare copy this public template into your GitHub or GitLab account.
4. Enter `NEAR_AI_API_KEY` when the deployment form asks for the secret.
5. Open the resulting `workers.dev` URL and select **Verify environment**.

Each deployment uses the deployer's Cloudflare account, provider key, quota, and bill. The key is stored as a Worker secret and is never included in browser JavaScript.

> The generated `workers.dev` URL is public. This template does not provision Cloudflare Access or an account-wide spending cap. Do not share a deployment backed by a billable key until you add an access or rate-limit boundary appropriate for your account.

## Deliberately small scope

- One allowlisted model: `Qwen/Qwen3.5-122B-A10B`
- One prompt and one completion at a time
- Browser-side TDX and NVIDIA evidence verification
- Browser-side encryption, decryption, and exact Ed25519 receipt verification
- Ciphertext-only Cloudflare relay
- No accounts, uploads, tools, RAG, model picker, catalog crawler, persistence, or custom GPU provisioning

## Honest boundary

This is a synthetic-data demonstration, not a production secret-release system. It does not prove that traffic metadata is hidden, that arbitrary workloads are safe, or that the service is approved for customer, regulated, CUI, PHI, or production data. Provider and project administrators still control infrastructure and availability. Measurement policy can require an update when the provider changes the measured workload.

## Local verification

```bash
npm ci
cp .dev.vars.example .dev.vars
# Replace the placeholder locally. Never commit .dev.vars.
npm run check
npm run dev:worker
```

The application is served at `http://localhost:8787`. A provider key is required only for the encrypted completion and signature routes. Fresh attestation and the full local build can be exercised without storing a provider key in source.

Validate the Worker package without deploying it:

```bash
npx wrangler deploy --dry-run --outdir /tmp/tee-proof-dry-run
```

## Security model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Updating the pinned workload

The browser fails closed if the verified MRTD, RTMR set, Compose hash, OS image hash, GPU architecture, device count, or report binding differs from `src/lib/policy.ts`. A provider update is not a reason to weaken the checks. Re-qualify the exact route, review the measured Compose source and runtime identity, update one complete measurement profile, and rerun the negative suite.

## Development

```bash
npm ci
npm run check
```

The repository uses Workers Static Assets, React, Vite, TypeScript, Vitest, Oxlint, `@phala/dcap-qvl` for Intel quote verification, NVIDIA NRAS/JWKS verification, and Noble cryptography for the NEAR E2EE v2 wire protocol.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
