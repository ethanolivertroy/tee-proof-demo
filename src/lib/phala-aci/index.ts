/**
 * ACI (Attested Confidential Inference) verifier primitives for this demo's
 * reviewed Phala profile.
 *
 * Provenance: adapted from https://github.com/Dstack-TEE/private-ai-gateway
 * `clients/verifier-ts` and `spec/aci.md` at commit
 * 898f19f36978102aade8785632eb36f8d4459337 (2026-09-01), Apache-2.0, modified
 * for this browser demo: hashing and signatures use the same `@noble`
 * primitives as the rest of src/lib instead of Web Crypto, the E2EE v2 channel
 * (`spec/e2ee-v2.md` at the same commit) is implemented here because the
 * upstream package only verifies, and a keyset-lifetime bound is enforced.
 *
 * Every `§` citation in this directory refers to `spec/aci.md` at that commit
 * unless it is prefixed `e2ee-v2`, which refers to `spec/e2ee-v2.md`. Byte
 * exact expectations come from `spec/test-vectors.md` and
 * `spec/e2ee-v2-test-vectors.md`.
 *
 * Scope: report binding (§9.1 checks 2-3), receipts and body hashes (§9.3),
 * attested sessions (§8, §9.2), and the E2EE v2 channel. The hardware quote
 * (§9.1 check 1), dstack provenance and custody (checks 4-5), and the declared
 * TLS channel (check 6) are composed in ../phala-verifier-core.ts and
 * ../phala-dstack.ts.
 */

// Canonicalization (Appendix A)
export { canonicalize, jcsBytes } from './jcs'
export type { JcsValue } from './jcs'

// Decoding and Ed25519 verification under attested keys
export { fromBase64, fromHex, verifyEd25519 } from './crypto'

// Digest constructions (Appendix A, §3.1, §3.2, §7.2)
export {
  attestationStatement,
  computeKeysetDigest,
  computeReportData,
  receiptSigningBytes,
  reportDataSlot,
  sha256Prefixed,
} from './digest'

// Attested sessions: content addressing and evidence (§8, §9.2)
export { checkSessionApiVersion, checkSessionEvidence, computeSessionId } from './session'

// Receipt verification (§9.3)
export { checkRequestBodyHash, checkResponseBodyHash, findEvent, hashBody, verifyReceipt } from './receipt'

// Report binding (§9.1 checks 2-3, no hardware quote)
export { MAX_KEYSET_LIFETIME_SECONDS, verifyReportBinding } from './report'
export type { ReportBindingOptions } from './report'

// E2EE v2 AAD builders and channel (e2ee-v2 §4-§6)
export { requestAad, responseAad } from './e2ee'
export type { AadCommon } from './e2ee'
export { openE2eeChannel } from './e2ee-channel'
export type { ApprovedE2eeKey, E2eeChannel } from './e2ee-channel'

// Errors
export { AciError, AciFormatError } from './errors'

// Wire & result types
export type {
  KeysetKey,
  TlsKeyPin,
  WorkloadKeyset,
  SourceProvenance,
  Attestation,
  AttestationReport,
  ReceiptEnvelope,
  ReceiptEvent,
  ReceiptPayload,
  SessionEvidence,
  SessionRecord,
  Check,
  ReceiptVerification,
  ReportVerification,
} from './types'
