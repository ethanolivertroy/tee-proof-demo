/**
 * The ACI digest constructions (Appendix A, §3.1, §3.2, §7.2). Artifacts the
 * service builds are hashed over the JCS form of the parsed document; the
 * attestation statement is the one report payload a verifier constructs
 * itself, as a fixed byte template whose inputs are restricted so no JSON
 * escaping is ever needed. Each function returns the exact bytes the spec pins
 * in spec/test-vectors.md, so they double as the byte-for-byte reference.
 */

import { sha256Hex } from '../crypto'
import { AciFormatError } from './errors'
import { jcsBytes } from './jcs'
import type { JcsValue } from './jcs'
import type { ReceiptEnvelope } from './types'

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/
const NONCE_RE = /^[0-9a-f]{64}$/

/**
 * `sha256:<lowercase-hex>` digest string of the given bytes, the ACI digest
 * form (Appendix A) used for keyset digests, body hashes, and evidence digests.
 */
export function sha256Prefixed(bytes: Uint8Array): string {
  return 'sha256:' + sha256Hex(bytes)
}

/** `workload_keyset_digest` (§3.1): sha256 over the keyset's JCS form, as parsed. */
export function computeKeysetDigest(keyset: JcsValue): string {
  return sha256Prefixed(jcsBytes(keyset))
}

/**
 * The exact attestation-statement bytes (§3.2) for a keyset digest and the
 * nonce the client sent. `null`/`undefined` means the query parameter was
 * omitted, which puts the JSON literal `null` in the template. Inputs outside
 * the spec-pinned formats throw {@link AciFormatError}.
 */
export function attestationStatement(keysetDigest: string, nonce: string | null | undefined): Uint8Array {
  if (!DIGEST_RE.test(keysetDigest)) {
    throw new AciFormatError(`keyset digest is not sha256:<64-hex>: "${keysetDigest}"`)
  }
  if (nonce != null && !NONCE_RE.test(nonce)) {
    throw new AciFormatError('nonce must be exactly 64 lowercase hex characters (§3.2)')
  }
  const noncePart = nonce == null ? 'null' : `"${nonce}"`
  return new TextEncoder().encode(
    `{"keyset_digest":"${keysetDigest}","nonce":${noncePart},"purpose":"aci.report_data.v1"}`,
  )
}

/**
 * `report_data` (§3.2): SHA-256 of the attestation statement, as bare lowercase
 * hex (it fills a report-data slot, not an ACI digest string). The TEE places
 * these 32 bytes zero-padded to 64 in the quote's report-data field.
 */
export function computeReportData(keysetDigest: string, nonce: string | null | undefined): string {
  return sha256Hex(attestationStatement(keysetDigest, nonce))
}

/**
 * The 64-byte report-data slot a TDX quote must carry for `report_data` (§3.2):
 * the digest in bytes 0-31, zero in bytes 32-63.
 */
export function reportDataSlot(reportDataHex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(reportDataHex)) {
    throw new AciFormatError('report_data is not 32 bytes of lowercase hex (§3.2)')
  }
  const slot = new Uint8Array(64)
  for (let i = 0; i < 32; i++) slot[i] = Number.parseInt(reportDataHex.slice(i * 2, i * 2 + 2), 16)
  return slot
}

/**
 * The bytes a receipt signature covers (§7.2): the JCS form of the whole
 * document with only `signature` removed. Unknown members and events are kept
 * by canonicalizing the object as parsed (Appendix B).
 */
export function receiptSigningBytes(document: ReceiptEnvelope): Uint8Array {
  const { signature: _omitted, ...unsigned } = document
  return jcsBytes(unsigned as JcsValue)
}
