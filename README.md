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

1. The browser makes sure that the access token of the deployment owner is correct. If the token is not correct, the flow does not start.
2. The browser selects one of the two compiled provider and model policies.
3. The browser makes a new 32-byte challenge.
4. The browser examines the confidential-computing evidence of the selected provider.
5. The browser encrypts the prompt after the verification is successful. It does not encrypt the prompt before.
6. The browser sends the ciphertext through a small Cloudflare Worker relay.
7. The browser decrypts the completion.
8. The browser makes sure that the exact request bytes and response bytes are correct. It uses an attested signing key or receipt key for this check.

The Worker does these tasks:

- The Worker supplies the static assets.
- The Worker applies the shared owner gate to the routes that the provider bills.
- The Worker permits connections to only the two approved upstream origins.
- The Worker limits the size of the request bodies during the stream.
- The Worker sends the ciphertext to the provider and back.

**The Worker is not a hardware TEE.**

## Reviewed routes

| Provider | Fixed model | Browser verification | Exact completion authentication |
| --- | --- | --- | --- |
| NEAR AI Cloud | `deepseek-ai/DeepSeek-V4-Flash` | Intel TDX quote, measured workload, eight NVIDIA Hopper GPU verdicts, fresh nonce, and attested model key | Ed25519 signature over `model:SHA256(exact encrypted request bytes):SHA256(exact encrypted response bytes)` |
| Phala Cloud | `openai/gpt-oss-20b` | Intel TDX quote, replayed event log, measured Compose/source commit, dstack KMS custody, fresh nonce, TLS/keyset bindings, and ACI E2EE keys | Signed ACI receipt that binds the cleartext request, the encrypted wire response, the decrypted response, the model, the endpoint, and the verified upstream session |

If you change the model, the demo removes the old evidence. The demo does not have these functions:

- An origin that the caller can select
- A model identifier that the caller can supply
- A general chat history
- A file upload
- A tool call
- RAG
- A shell or code-execution surface

## Spend protection

The public can get access to a deployed `workers.dev` hostname. Thus this template must have a third secret, `DEMO_ACCESS_TOKEN`. The Worker rejects each chat, signature, receipt, and session route that the provider bills, unless the browser supplies the correct token.

- Use a random value that is different for each deployment. Use between 20 and 256 characters.
- The browser keeps the token in memory for the current tab. The browser does not write the token to local storage.
- The Worker removes the token before it sends the request to a provider.
- The static assets and the attestation endpoints stay public. These routes do not use the provider credentials of the deployer.
- The gate is a shared secret. The gate is not SSO, not a rate limit, and not a fixed limit on provider costs.

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
- The browser examines the Phala workload ID, the measurements, the measured Compose hash, the measured source commit, the KMS custody, the E2EE key, the receipt key, and the TLS binding.
- The quote verification is a large computation. A browser worker does this computation in isolation.
- The browser does not release the prompt before the selected policy is verified.
- The evidence becomes invalid when the model changes or when the time limit is reached.
- The browser makes sure that the exact completion bytes are correct after decryption.
- The response schemas are strict. They reject unknown metadata and metadata that contains plaintext.
- The Worker body limits apply also when there is no `Content-Length`. The Worker cancels a stream immediately when the stream is larger than the limit.
- The Worker examines the access token before it uses the provider credentials or the paid upstream routes.
- The provider credentials stay in the Worker secrets. The Worker does not send the credentials to the browser.

## Important limits

Use synthetic data only.

This proof does **not** show:

- that the demo is approved for regulated or sensitive production data;
- that the demo is safe for other workloads or for models that a user selects;
- that the demo is a complete production design for secret release;
- that access control is related to identity, if you do not turn on Cloudflare Access;
- that there is a fixed limit on costs, or that the providers are always available;
- that IP addresses, timing, ciphertext length, or other traffic metadata are hidden;
- that trust in the provider, Intel, NVIDIA, the certificate authority, Cloudflare, or the code review is not necessary; or
- that Cloudflare Workers operate in the hardware TEE that the demo shows.

The Phala measurements and the NEAR measurements can change after a reviewed deployment. This change can be correct. The demo then fails closed. The demo stays closed until the new evidence and the measured source are qualified again, and the compiled policy is updated.

## Validation

```sh
npm run check
npm run deploy -- --dry-run
npm audit --omit=dev --audit-level=moderate
```

The screenshots in the repository were made at the `1440×1000` and `390×844` viewports. They were made after successful live attestation verification. The full-page PNG dimensions are larger because the page has vertical scroll.

The validation of this repository did not deploy a Cloudflare Worker. The validation did not start a paid confidential-model completion.

## Project map

```text
src/App.tsx                         fixed two-provider proof UI and owner gate
src/lib/policy.ts                  compiled provider/model/measurement policies
src/lib/attestation.ts             NEAR Intel TDX + NVIDIA verification flow
src/lib/phala-verifier-core.ts     Phala TDX, dstack, KMS, key, and source checks
src/lib/phala-aci/                 Phala ACI binding, E2EE, and receipt primitives
src/lib/crypto.ts                  browser E2EE and Ed25519 response verification
worker/index.ts                    gated, origin-pinned ciphertext relay
public/_headers                    browser security headers
docs/screenshots/                  committed desktop and mobile previews
tests/                             crypto, Worker, protocol, and Phala hardening tests
```

See [SECURITY.md](SECURITY.md) for the report instructions and the current dependency note.

## License

Apache-2.0. See [LICENSE](LICENSE).
