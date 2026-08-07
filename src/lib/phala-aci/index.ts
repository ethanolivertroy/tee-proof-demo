/**
 * ACI verifier primitives for this demo's reviewed Phala profile.
 *
 * Level 1 receipt verification (§10.2) is implemented against an established
 * keyset. {@link verifyReportBinding} adds the cryptographic-binding checks of
 * Level 2 (§10.1 checks 2-6); hardware quote, key custody, and provenance checks
 * (§10.1 checks 1, 7-10) are composed in `phala-verifier-core.ts`. Hashing and
 * signature verification use the same `@noble` primitives as the rest of
 * src/lib (see ../crypto and ../encoding); the E2EE channel uses Web Crypto
 * X25519 + AES-GCM.
 */

// Canonicalization (§3)
export { canonicalize, jcsBytes } from './jcs'
export type { JcsValue } from './jcs'

// Signature verification under attested keys, and ACI's error-typed hex decoding
export { fromHex, verifySignature } from './crypto'

// Digest & canonical-signing-bytes constructions (§4, §8.5, §9.2)
export {
  computeKeysetDigest,
  computeReportData,
  computeSessionId,
  computeWorkloadId,
  keysetEndorsementPayload,
  receiptSigningBytes,
  sha256Prefixed,
} from './digest'

// E2EE AAD builders (§7.3)
export { requestAad, responseAad } from './e2ee'
export type { AadCommon } from './e2ee'

// E2EE channel to a verified workload: encrypt requests, decrypt replies (§7)
export { openE2eeChannel } from './e2ee-channel'
export type { ApprovedE2eeKey, E2eeChannel } from './e2ee-channel'

// Level 1 receipt verification (§10.2)
export {
  checkRequestBodyHash,
  checkResponseCleartextHash,
  checkResponseWireHash,
  findEvent,
  hashBody,
  verifyReceipt,
} from './receipt'

// Level 2 report-binding checks (§10.1 checks 2-6, no hardware quote)
export { verifyReportBinding } from './report'
export type { ReportBindingOptions } from './report'

// Errors
export { AciError, AciFormatError, UnsupportedAlgorithmError } from './errors'

// Wire & result types
export type {
  PublicKey,
  WorkloadIdentity,
  ReceiptSigningKey,
  WorkloadKeyset,
  ReceiptSignature,
  ReceiptEvent,
  Receipt,
  Endorsement,
  Attestation,
  AttestationReport,
  SessionEvidence,
  SessionRecord,
  Check,
  ReceiptVerification,
  ReportVerification,
} from './types'
