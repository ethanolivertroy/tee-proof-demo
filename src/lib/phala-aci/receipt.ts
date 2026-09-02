/**
 * Receipt verification (§7, §9.3). A receipt is one JSON document; its
 * `signature` is Ed25519 over JCS(document minus `signature`) under a key the
 * established keyset lists. "Established" means a keyset whose digest the
 * caller verified through {@link verifyReportBinding} together with the
 * hardware, provenance, and custody checks of the verifier profile.
 */

import { fromHex, verifyEd25519 } from './crypto'
import { receiptSigningBytes, sha256Prefixed } from './digest'
import { AciFormatError } from './errors'
import type { Check, ReceiptEnvelope, ReceiptEvent, ReceiptPayload, ReceiptVerification, WorkloadKeyset } from './types'

/**
 * §9.3 checks 1-2: the `signature` member verifies over JCS(document minus
 * `signature`) under the keyset entry `key_id` names, and the document's
 * `api_version` is `aci/1` and its `workload_keyset_digest` equals the
 * established digest.
 *
 * Returns per-check results plus the document read as its payload; a failed
 * check is `ok: false`, never thrown.
 */
export function verifyReceipt(document: ReceiptEnvelope, keyset: WorkloadKeyset, establishedDigest: string): ReceiptVerification {
  const checks: Check[] = []

  // §9.3 check 1: Ed25519 over JCS(document minus `signature`). The attested
  // entry decides the algorithm (§7.2); Appendix B defines only ed25519, so an
  // entry carrying anything else is rejected rather than guessed at.
  const signingKeys = Array.isArray(keyset.receipt_signing_keys) ? keyset.receipt_signing_keys : []
  const keyEntry = signingKeys.find((k) => k.key_id === document.key_id)
  if (!keyEntry) {
    checks.push({ name: 'signature', ok: false, detail: `key_id "${String(document.key_id)}" not in receipt_signing_keys` })
  } else if (keyEntry.algo !== 'ed25519') {
    checks.push({ name: 'signature', ok: false, detail: `unsupported signature algo "${keyEntry.algo}"` })
  } else if (typeof document.signature !== 'string') {
    checks.push({ name: 'signature', ok: false, detail: 'signature is not a string' })
  } else {
    let ok = false
    let detail = `ed25519 verification failed under "${document.key_id}"`
    try {
      ok = verifyEd25519(fromHex(keyEntry.public_key), fromHex(document.signature), receiptSigningBytes(document))
    } catch (error) {
      if (!(error instanceof AciFormatError)) throw error
      detail = `malformed signature material: ${error.message}`
    }
    checks.push({ name: 'signature', ok, ...(ok ? {} : { detail }) })
  }

  const payload = document as unknown as ReceiptPayload
  // Appendix B: reject receipts with a foreign api_version.
  const versionOk = payload.api_version === 'aci/1'
  checks.push({
    name: 'api_version',
    ok: versionOk,
    ...(versionOk ? {} : { detail: `api_version "${String(payload.api_version)}" is not "aci/1"` }),
  })
  // §9.3 check 2: the document binds back to the established keyset.
  const digestOk = payload.workload_keyset_digest === establishedDigest
  checks.push({
    name: 'workload_keyset_digest',
    ok: digestOk,
    ...(digestOk ? {} : { detail: `document ${String(payload.workload_keyset_digest)} != established ${establishedDigest}` }),
  })

  return { ok: checks.every((c) => c.ok), checks, payload }
}

/** Find the first event of a given type in a receipt payload's event log. */
export function findEvent(payload: ReceiptPayload, type: string): ReceiptEvent | undefined {
  if (!Array.isArray(payload.event_log)) return undefined
  return payload.event_log.find((e) => e?.type === type)
}

/**
 * `sha256:<hex>` of raw body bytes, the form ACI body hashes use (Appendix A).
 * Accepts a string (UTF-8 encoded) or raw bytes.
 */
export function hashBody(body: Uint8Array | string): string {
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body
  return sha256Prefixed(bytes)
}

/**
 * §9.3 check 3: `request.received.body_hash` matches the plaintext wire body,
 * or the compact post-decryption JSON body for E2EE v2 (e2ee-v2.md §8).
 * Returns false when the event or its hash is absent.
 */
export function checkRequestBodyHash(payload: ReceiptPayload, requestBody: Uint8Array | string): boolean {
  return eventHashMatches(payload, 'request.received', requestBody)
}

/**
 * §9.3 check 4: `response.returned.body_hash` matches the response bytes this
 * client received off the wire, including encrypted E2EE field values
 * (e2ee-v2.md §8). Returns false when the event or its hash is absent.
 */
export function checkResponseBodyHash(payload: ReceiptPayload, responseBody: Uint8Array | string): boolean {
  return eventHashMatches(payload, 'response.returned', responseBody)
}

function eventHashMatches(payload: ReceiptPayload, type: string, body: Uint8Array | string): boolean {
  const expected = findEvent(payload, type)?.body_hash
  if (typeof expected !== 'string') return false
  return hashBody(body) === expected
}
