/**
 * Phala completion audit: spec/aci.md §9.3 checks 1-6 plus the §9.2 session
 * audit for the aggregator hop (sections cited from ./phala-aci/index.ts).
 * Inputs are the receipt id the response carried, the keyset established by
 * verifyPhalaGateway, the plaintext request the browser restored, and the
 * exact encrypted response bytes it received. Every failure throws.
 */

import {
  checkRequestBodyHash,
  checkResponseBodyHash,
  checkSessionApiVersion,
  checkSessionEvidence,
  computeSessionId,
  findEvent,
  receiptSigningBytes,
  verifyReceipt,
  type ReceiptEnvelope,
  type ReceiptEvent,
  type ReceiptPayload,
  type SessionRecord,
  type WorkloadKeyset,
} from './phala-aci'
import { assert, assertPlainObject, isRecord } from './guards'
import { accessHeaders, fetchJson } from './http'
import type { PhalaModelPolicy } from './policy'
import type { PhalaCompletionReceipt } from './types'

const RECEIPT_ID = /^rcpt-[0-9a-f]{24}$/
const SESSION_ID = /^[0-9a-f]{64}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/

function requireEvent(payload: ReceiptPayload, type: string): ReceiptEvent {
  const found = findEvent(payload, type)
  assert(found, `Phala receipt is missing ${type}`)
  return found
}

/**
 * §9.3 check 5 and §7.5: exactly one `upstream.verified` event records
 * verified, required serving of the requested model and cites a session.
 * Best-effort (`required: false`) or failed serving is refused.
 */
export function requireVerifiedUpstream(payload: ReceiptPayload, model: string): { sessionId: string } {
  const events = payload.event_log.filter((event) => event.type === 'upstream.verified')
  assert(events.length > 0, 'Phala receipt records no upstream verification')
  const verified = events.filter((event) => event.result === 'verified')
  assert(verified.length === 1, 'Phala receipt does not record exactly one verified upstream')
  const event = verified[0]!
  assert(event.required === true, 'Phala upstream verification was not required')
  assert(event.model_id === model, 'Phala upstream model mismatch')
  assert(typeof event.session_id === 'string' && SESSION_ID.test(event.session_id), 'Phala upstream session id is invalid')
  return { sessionId: event.session_id }
}

function claimAsserted(claims: Record<string, unknown>, name: string, sources: readonly string[]): void {
  const claim = claims[name]
  assert(isRecord(claim), `Phala upstream claim is missing: ${name}`)
  assert(claim.status === 'asserted' && typeof claim.source === 'string' && sources.includes(claim.source), `Phala upstream claim is not acceptable: ${name}`)
}

/**
 * §9.2 checks 1-3 and the §9.3 check 6 window: the fetched record hashes to
 * the cited id, is `aci/1`, carries evidence that hashes to its digest, was
 * produced by the pinned verifier over an HTTPS origin it TLS-pinned, asserts
 * the hardware and GPU claims this policy demands, and covers `served_at`.
 * The deep audit (§9.2 check 4) is out of scope for this demo: the upstream
 * NEAR-style evidence is left for the pinned verifier.
 */
export function auditSession(record: unknown, sessionId: string, servedAt: number, policy: PhalaModelPolicy): SessionRecord {
  assertPlainObject(record, 'Invalid Phala upstream session')
  const session = record as unknown as SessionRecord
  assert(checkSessionApiVersion(session), 'Phala session api_version is not aci/1')
  assert(computeSessionId(session) === sessionId, 'Phala session content hash mismatch')
  assert(session.verifier_id === policy.requiredUpstreamVerifierId, `Unexpected Phala upstream verifier: ${String(session.verifier_id)}`)
  assert(typeof session.endpoint === 'string' && session.endpoint.startsWith('https://'), 'Phala upstream origin is not HTTPS')
  assert(Array.isArray(session.channel_binding) && session.channel_binding.some((binding) =>
    isRecord(binding) && binding.type === 'tls_spki_sha256' && binding.origin === session.endpoint
    && typeof binding.spki_sha256 === 'string' && /^[0-9a-f]{64}$/.test(binding.spki_sha256)), 'Phala session is not TLS-pinned to its upstream origin')
  assert(isRecord(session.claims), 'Phala upstream claims are missing')
  claimAsserted(session.claims, 'tee_attested', ['hardware_proven'])
  claimAsserted(session.claims, 'gpu_attested', ['verifier_derived'])
  claimAsserted(session.claims, 'tcb_up_to_date', ['hardware_proven', 'verifier_derived'])
  assert(Number.isSafeInteger(session.established_at) && Number.isSafeInteger(session.expires_at), 'Phala session validity window is invalid')
  assert(servedAt >= session.established_at && servedAt <= session.expires_at, 'Phala receipt was served outside the session validity window')
  assert(isRecord(session.evidence) && typeof session.evidence.digest === 'string' && DIGEST.test(session.evidence.digest), 'Phala session evidence digest is missing or invalid')
  assert(checkSessionEvidence(session.evidence), 'Phala session evidence does not hash to its digest')
  return session
}

export async function verifyPhalaCompletionReceipt(input: {
  receiptId: string
  policy: PhalaModelPolicy
  keyset: WorkloadKeyset
  workloadKeysetDigest: string
  plaintextRequestBody: string
  responseWireBody: string
  accessToken: string
  signal?: AbortSignal
}): Promise<PhalaCompletionReceipt> {
  assert(RECEIPT_ID.test(input.receiptId), 'Invalid Phala receipt id')
  const fetchEvidence = (path: string) => fetchJson(`${path}?model=${encodeURIComponent(input.policy.id)}`, {
    headers: accessHeaders(input.accessToken),
    signal: input.signal,
  })
  const document = await fetchEvidence(`/api/phala/receipts/${input.receiptId}`)
  assertPlainObject(document, 'Invalid Phala receipt')
  assert(typeof document.key_id === 'string' && typeof document.signature === 'string', 'Phala receipt is unsigned')
  assert(document.key_id === input.policy.receiptKeyId, 'Phala receipt used an unapproved signing key')

  // §9.3 checks 1 and 2.
  const verified = verifyReceipt(document as ReceiptEnvelope, input.keyset, input.workloadKeysetDigest)
  assert(verified.ok, `Phala receipt verification failed: ${verified.checks.filter((check) => !check.ok).map((check) => check.name).join(', ')}`)
  const receipt = verified.payload
  assert(receipt.receipt_id === input.receiptId, 'Phala receipt identity mismatch')
  assert(receipt.model === input.policy.model, 'Phala receipt model mismatch')
  assert(receipt.endpoint === '/v1/chat/completions' && receipt.method === 'POST', 'Phala receipt endpoint mismatch')
  assert(Number.isSafeInteger(receipt.served_at), 'Phala receipt served_at is invalid')
  assert(Array.isArray(receipt.event_log) && receipt.event_log.every((event) => isRecord(event) && typeof event.type === 'string'), 'Phala receipt event log is invalid')
  assert(receipt.event_log[0]?.type === 'request.received', 'Phala receipt does not begin with request.received')

  // §9.3 checks 3 and 4 under the e2ee-v2 §8 rules: the request hash covers
  // the restored plaintext body, the response hash the encrypted wire bytes.
  assert(checkRequestBodyHash(receipt, input.plaintextRequestBody), 'Phala receipt request hash mismatch')
  assert(checkResponseBodyHash(receipt, input.responseWireBody), 'Phala receipt response hash mismatch')
  // The prompt was forwarded, so the forwarded hash must be present. It differs
  // from request.received because the aggregator consumes the §5.3 serving
  // constraint before forwarding, which the spec defines as the visible rewrite.
  const forwarded = requireEvent(receipt, 'request.forwarded')
  assert(typeof forwarded.body_hash === 'string' && DIGEST.test(forwarded.body_hash), 'Phala receipt forwarded hash is invalid')

  // §9.3 checks 5 and 6.
  const { sessionId } = requireVerifiedUpstream(receipt, input.policy.model)
  const session = auditSession(await fetchEvidence(`/api/phala/sessions/${sessionId}`), sessionId, receipt.served_at, input.policy)

  return {
    provider: 'phala-cloud',
    model: input.policy.model,
    requestHash: String(requireEvent(receipt, 'request.received').body_hash),
    responseHash: String(requireEvent(receipt, 'response.returned').body_hash),
    signer: `${receipt.workload_keyset_digest}#${receipt.key_id}`,
    signature: document.signature,
    signedText: new TextDecoder().decode(receiptSigningBytes(document as ReceiptEnvelope)),
    verifiedAt: new Date().toISOString(),
    receiptId: receipt.receipt_id,
    workloadKeysetDigest: receipt.workload_keyset_digest,
    sessionId,
    upstreamEndpoint: session.endpoint as string,
  }
}
