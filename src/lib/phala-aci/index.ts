/**
 * Adapted ACI verifier primitives for this demo's reviewed Phala profile.
 *
 * Level 1 receipt verification (§10.2) is implemented against an established
 * keyset. {@link verifyReportBinding} adds the cryptographic-binding checks of
 * Level 2 (§10.1 checks 2–6); hardware quote, key custody, and provenance checks
 * (§10.1 checks 1, 7–10) are composed in `phala-verifier-core.ts`. SHA-256 and
 * Ed25519 use Web Crypto; secp256k1 uses `@noble/curves`.
 */

// Canonicalization (§3)
export { canonicalize, jcsBytes } from './jcs.js';
export type { JcsValue } from './jcs.js';

// Crypto primitives (Web Crypto plus @noble/curves secp256k1)
export {
  sha256,
  sha256Hex,
  sha256Prefixed,
  verifyEd25519,
  verifySignature,
  toHex,
  fromHex,
} from './crypto.js';

// Digest & canonical-signing-bytes constructions (§4, §8.5, §9.2)
export {
  computeWorkloadId,
  computeKeysetDigest,
  attestationStatement,
  computeReportData,
  keysetEndorsementPayload,
  keysetRevocationPayload,
  receiptSigningBytes,
  sessionMaterial,
  computeSessionId,
} from './digest.js';

// E2EE AAD builders (§7.3)
export {
  requestAad,
  requestAadString,
  responseAad,
  responseAadString,
} from './e2ee.js';
export type { AadCommon } from './e2ee.js';

// E2EE channel to a verified workload — encrypt requests, decrypt replies (§7)
export { openE2eeChannel } from './e2ee-channel.js';
export type { ApprovedE2eeKey, E2eeChannel } from './e2ee-channel.js';

// Level 1 receipt verification (§10.2)
export {
  verifyReceipt,
  findEvent,
  hashBody,
  checkRequestBodyHash,
  checkResponseWireHash,
  checkResponseCleartextHash,
} from './receipt.js';

// Level 2 report-binding checks (§10.1 checks 2–6, no hardware quote)
export { verifyReportBinding } from './report.js';
export type { ReportBindingOptions } from './report.js';

// Errors
export { AciError, AciFormatError, UnsupportedAlgorithmError } from './errors.js';

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
} from './types.js';
