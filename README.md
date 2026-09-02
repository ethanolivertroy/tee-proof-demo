# TEE Proof

This demo gives proof of confidential inference. The browser does the verification. The demo has two reviewed provider routes.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ethanolivertroy/tee-proof-demo)
[![CI](https://github.com/ethanolivertroy/tee-proof-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/ethanolivertroy/tee-proof-demo/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Preview

<table>
  <tr>
    <th>NEAR AI Cloud · DeepSeek V4 Flash · desktop</th>
    <th>Phala Cloud · GPT-OSS 20B · mobile</th>
  </tr>
  <tr>
    <td width="70%"><img src="docs/screenshots/verified-near-desktop.png" alt="Desktop view showing the owner access gate, NEAR DeepSeek model selected, and successful Intel TDX plus eight-GPU NVIDIA verification" /></td>
    <td width="30%"><img src="docs/screenshots/verified-phala-mobile.png" alt="Mobile view showing Phala GPT-OSS selected and successful Intel TDX, measured source, dstack KMS, E2EE key, and receipt-key verification" /></td>
  </tr>
</table>

## What the demo shows

The browser does these steps for one synthetic prompt:

1. The browser sends the access token of the deployment owner to the Worker. The Worker rejects every `/api` route until the token is correct, so the flow does not start without it.
2. The browser selects one of the two compiled provider and model policies.
3. The browser makes a new 32-byte challenge.
4. The browser examines the confidential-computing evidence of the selected provider in an isolated browser worker.
5. The browser encrypts the prompt after the verification is successful. It does not encrypt the prompt before.
6. The browser sends the ciphertext through a small Cloudflare Worker relay.
7. The browser authenticates the exact encrypted request bytes and the exact encrypted response bytes. It uses the attested signing key or receipt key for this check.
8. The browser decrypts the completion. The text it shows is what the authenticated bytes decrypt to under the browser's own key.

The Worker does these tasks:

- The Worker supplies the static assets. These are the only public routes.
- The Worker applies the shared owner gate to every `/api` route, including the attestation relays.
- The Worker permits connections to only three fixed upstream origins: the NEAR endpoint, the Phala endpoint, and the NVIDIA attestation service.
- The Worker limits the size of the request bodies during the stream.
- The Worker sends the ciphertext to the provider and back. It removes the owner token first.

**The Worker is not a hardware TEE.**

### Network connections

| Who connects | To | Purpose |
| --- | --- | --- |
| Worker | `dsv4-flash.completions.near.ai` | NEAR attestation, chat, and signature routes |
| Worker | `inference.phala.com` | Phala attestation, chat, receipt, and session routes |
| Worker | `nras.attestation.nvidia.com` | NVIDIA GPU verdicts for the NEAR route |
| Browser | `nras.attestation.nvidia.com` | JWKS to check the NVIDIA verdict signatures |
| Browser worker | `pccs.phala.network`, `api.trustedservices.intel.com` | Intel TDX quote collateral |

The browser connections show the visitor's IP address and timing to those parties. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full boundary.

## Reviewed routes

| Provider | Fixed model | Browser verification | Exact completion authentication |
| --- | --- | --- | --- |
| NEAR AI Cloud | `deepseek-ai/DeepSeek-V4-Flash` | Intel TDX quote, measured workload, eight NVIDIA Hopper GPU verdicts, fresh nonce, and attested model key | Ed25519 signature over `model:SHA256(exact encrypted request bytes):SHA256(exact encrypted response bytes)` |
| Phala Cloud | `openai/gpt-oss-20b` | Intel TDX quote, replayed event log, measured Compose and source commit, dstack KMS custody, fresh nonce, keyset digest and expiry, TLS SPKI binding, and ACI E2EE keys | Signed ACI receipt that binds the plaintext request hash, the exact encrypted wire response hash, the model, the endpoint, the verified keyset digest, and the attested upstream session that served it |

The two trust chains differ. On the NEAR route the browser verifies the TDX quote and the eight GPU verdicts itself. On the Phala route the browser verifies the gateway TDX quote and the dstack chain before it sends the prompt. After the completion, the signed receipt cites an attested upstream session. The browser fetches that session record, checks its content address, its verifier identity, its TLS binding, and its claims, but it does not audit the upstream node's GPU evidence itself. That audit is the pinned verifier's job.

If you change the model, the demo removes the old evidence. The demo does not have these functions:

- An origin that the caller can select
- A model identifier that the caller can supply
- A general chat history
- A file upload
- A tool call
- RAG
- A shell or code-execution surface

## Spend protection

The public can get access to a deployed `workers.dev` hostname. Thus this template must have a third secret, `DEMO_ACCESS_TOKEN`. The Worker rejects every `/api` route unless the browser supplies the correct token. This includes the attestation and NVIDIA relays, so an anonymous visitor cannot use your Worker to send traffic to the providers.

- Use a random value that is different for each deployment. Use between 20 and 256 characters. The Worker answers 503 on every `/api` route if the configured token is missing or outside that range.
- The page holds the token in memory only. It does not write the token to local storage, and the input opts out of browser autofill.
- The Worker removes the token before it sends the request upstream.
- Only the static assets stay public.
- The gate is a shared secret. The gate is not SSO, not a rate limit, and not a fixed limit on provider costs. Add a Cloudflare rate-limiting rule on `/api/*` if you share the token widely.

For access control that is related to identity, turn on [Cloudflare Access on the Worker](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/#manage-access-to-workersdev) after the deployment: **Workers & Pages → your Worker → Settings → Domains & Routes → workers.dev → Enable Cloudflare Access**. Keep the owner token as a second control for the routes that the provider bills. Access settings are specific to each account and policy. Thus the repository cannot select or set the permitted identities of the operator through the generic Deploy Button.

## One-click deployment

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ethanolivertroy/tee-proof-demo)

The deployment flow builds the React app and makes a Worker with Static Assets. The flow asks for these secrets:

| Required secret | Purpose |
| --- | --- |
| `NEAR_AI_API_KEY` | Pays for the fixed NEAR route |
| `PHALA_API_KEY` | Pays for the fixed Phala route |
| `DEMO_ACCESS_TOKEN` | Controls access to each Worker route that the provider bills |

Make the access token on your local machine. This is an example:

```sh
openssl rand -hex 32
```

Do these steps after the deployment:

1. Open the URL that the deployment made.
2. Enter the same `DEMO_ACCESS_TOKEN`.
3. Turn on Cloudflare Access before you give the URL to other persons.
4. Set the budgets or limits on your provider accounts.

This repository does not set a fixed limit on your costs.

## Local operation

You must have Node.js 22 or a later version, npm, and your own provider keys.

```sh
npm install
cp .dev.vars.example .dev.vars
# Fill in NEAR_AI_API_KEY, PHALA_API_KEY, and DEMO_ACCESS_TOKEN.
npm run dev:worker
```

Open `http://localhost:8787`. Do not commit `.dev.vars`.

## Trust flow

```text
Browser                         Cloudflare Worker                    Confidential provider
  |                                      |                                      |
  |-- owner token check ---------------->| validate shared secret               |
  |<------------------------------- 204 --|                                      |
  |                                      |                                      |
  |-- fresh nonce + policy ------------->| fixed attestation origin ----------->|
  |<------------------------- evidence ---|<-------------------------------------|
  |                                      |                                      |
  | verify quote, freshness, policy, keys, measured source, and GPU evidence    |
  | FAIL CLOSED on stale, malformed, debug, substituted, or unapproved evidence |
  |                                      |                                      |
  | encrypt synthetic prompt             |                                      |
  |-- access token + ciphertext -------->| validate gate, shape, size, origin   |
  |                                      |-- provider key + ciphertext -------->|
  |                                      |<----- encrypted completion + proof --|
  |<----------- encrypted response ------|                                      |
  | decrypt + authenticate exact bytes   |                                      |
```

## Fail-closed properties

- The browser makes a new random nonce for each verification attempt.
- The evidence is valid for a maximum of five minutes on the local machine. This limit applies if the provider evidence is valid for a longer time.
- The endpoint allowlist and the model allowlist are exact and compiled.
- The browser examines the Intel TDX collateral. The browser rejects evidence from debug mode.
- The browser examines the NEAR workload measurements. The policy accepts only the exact signed verdicts from eight NVIDIA GPUs.
- The browser examines the Phala measurements, the replayed event log, the measured Compose hash, the measured source commit, the KMS custody, the keyset digest and expiry, the E2EE key, the receipt key, and the TLS binding.
- The quote verification is a large computation. A browser worker does this computation in isolation. The worker bundles contain no `eval`, and their Content Security Policy permits connections only to the Intel and Phala collateral endpoints.
- The browser does not release the prompt before the selected policy is verified.
- The evidence becomes invalid when the model changes or when the time limit is reached.
- The browser authenticates the exact encrypted request bytes and response bytes with the attested key before it shows the decrypted completion.
- The response schemas are strict. They reject unknown fields, more than one choice, and nested fields that can carry plaintext, such as `tool_calls` or `refusal`.
- The Worker body limits apply also when there is no `Content-Length`. The Worker cancels a stream immediately when the stream is larger than the limit. The browser applies the same streaming cap to every response it reads from the Worker.
- The Worker examines the access token on every `/api` route before it does anything else.
- The provider credentials stay in the Worker secrets. The Worker does not send the credentials to the browser.
- Every path the app is served from carries the same security headers, including `frame-ancestors 'none'`.

## Important limits

Use synthetic data only.

This proof does **not** show:

- that the demo is approved for regulated or sensitive production data;
- that the demo is safe for other workloads or for models that a user selects;
- that the demo is a complete production design for secret release;
- that access control is related to identity, if you do not turn on Cloudflare Access;
- that there is a fixed limit on costs, or that the providers are always available;
- that IP addresses, timing, ciphertext length, or other traffic metadata are hidden;
- that trust in the provider, Intel, NVIDIA, the certificate authority, Cloudflare, or the code review is not necessary;
- that the browser verifies the Phala upstream inference node directly. That evidence arrives inside the signed receipt; or
- that Cloudflare Workers operate in the hardware TEE that the demo shows.

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) states the full claim ladder for both routes.

The Phala measurements and the NEAR measurements can change after a reviewed deployment. This change can be correct. The demo then fails closed. The demo stays closed until the new evidence and the measured source are qualified again, and the compiled policy is updated.

## Validation

```sh
npm run check
npm run deploy -- --dry-run
npm audit --omit=dev --audit-level=moderate
```

The screenshots in the repository were made at the `1440×1000` and `390×844` viewports. They were made after successful live attestation verification. The full-page PNG dimensions are larger because the page has vertical scroll.

Live attestation verification for both routes was re-run on 2026-09-02 against the current provider endpoints, with fresh nonces and real Intel collateral. The NEAR route was also verified in a browser against a local Worker. The Phala receipt and session audit are covered by fixture tests and by live audits of the public session records. The validation did not deploy a Cloudflare Worker and did not start a paid confidential-model completion, so the paid completion path is validated against fixtures only.

## Project map

```text
src/App.tsx                        fixed two-provider proof UI and owner gate
src/lib/policy.ts                  compiled provider/model/measurement policies
src/lib/http.ts                    the one bounded client boundary to the Worker
src/lib/attestation.ts             NEAR Intel TDX + NVIDIA verification flow
src/lib/phala-verifier-core.ts     Phala TDX, dstack, KMS, key, and source checks
src/lib/phala-aci/                 Phala ACI client adapted from Dstack-TEE/private-ai-gateway
src/lib/crypto.ts                  browser E2EE and Ed25519 response verification
worker/index.ts                    gated, origin-pinned ciphertext relay
public/_headers                    security headers for every path and both verifier workers
scripts/third-party-notices.mjs    generates THIRD_PARTY_NOTICES.txt at build time
docs/THREAT_MODEL.md               two-route claim ladder and boundary
docs/screenshots/                  committed desktop and mobile previews
tests/                             crypto, Worker, protocol, and Phala hardening tests
```

See [SECURITY.md](SECURITY.md) for the report instructions and the current dependency note. See [NOTICE](NOTICE) for provenance of the adapted code.

## License

Apache-2.0. See [LICENSE](LICENSE).
