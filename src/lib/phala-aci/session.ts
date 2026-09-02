/**
 * Attested-session helpers (§8, §9.2). A session is content-addressed: its id
 * is the SHA-256 of the JCS form of the served document, and the signed
 * receipt commits to that id. There is no session signature.
 */

import { sha256Hex } from '../crypto'
import { fromBase64 } from './crypto'
import { sha256Prefixed } from './digest'
import { jcsBytes } from './jcs'
import type { JcsValue } from './jcs'
import type { SessionEvidence, SessionRecord } from './types'

/** `session_id` (§8): bare 64-hex sha256 of the JCS form of the parsed document. */
export function computeSessionId(record: JcsValue): string {
  return sha256Hex(jcsBytes(record))
}

/** Appendix B: reject session documents whose `api_version` is not `aci/1`. */
export function checkSessionApiVersion(record: Pick<SessionRecord, 'api_version'>): boolean {
  return record.api_version === 'aci/1'
}

/**
 * §9.2(2): `evidence.data` decodes and hashes to `evidence.digest`.
 * Returns false when the data URI is absent, malformed, or does not hash.
 */
export function checkSessionEvidence(evidence: SessionEvidence | null | undefined): boolean {
  if (evidence == null || typeof evidence !== 'object') return false
  const { digest, data } = evidence
  if (typeof digest !== 'string' || typeof data !== 'string') return false
  const comma = data.indexOf(',')
  if (!data.startsWith('data:') || comma < 0 || !data.slice(0, comma).endsWith(';base64')) return false
  let bytes: Uint8Array
  try {
    bytes = fromBase64(data.slice(comma + 1))
  } catch {
    return false
  }
  return sha256Prefixed(bytes) === digest
}
