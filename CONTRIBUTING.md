# Contributing

Keep this repository a proof, not a platform.

1. Open an issue before adding providers, models, accounts, persistence, uploads, tools, or background catalog jobs.
2. Keep origins and model identifiers compile-time fixed. No request field may select an upstream hostname or credential.
3. Add a denial test before changing an attestation, cryptographic, receipt, or relay rule.
4. Use synthetic data and your own provider credentials.
5. Run `npm run check` and `npx wrangler deploy --dry-run` before opening a pull request.

Do not commit `.dev.vars`, `.env`, quote captures containing identifying metadata, provider credentials, or production prompts.
