import {
  canonicalize,
  checkRequestBodyHash,
  checkResponseCleartextHash,
  checkResponseWireHash,
  computeSessionId,
  hashBody,
  receiptSigningBytes,
  sha256Prefixed,
  verifyReceipt,
  type JcsValue,
  type Receipt,
  type ReceiptEvent,
  type SessionRecord,
  type WorkloadKeyset,
} from './phala-aci'
import { assert, isRecord } from './guards'
import type { PhalaModelPolicy } from './policy'
import type { CompletionReceipt } from './types'

function event(receipt: Receipt, type: string): ReceiptEvent {
  const found = receipt.event_log.find((entry) => entry.type === type)
  assert(found, `Phala receipt is missing ${type}`)
  return found
}

export function assertResponseTransparency(receipt: Receipt): void {
  const returned = event(receipt, 'response.returned')
  const received = receipt.event_log.find((entry) => entry.type === 'response.received')
  const cleartextChanged = received !== undefined && received.cleartext_hash !== returned.cleartext_hash
  const wireChanged = returned.wire_hash !== returned.cleartext_hash
  if (cleartextChanged || wireChanged) event(receipt, 'transparency.response_modified')
}

function claimAsserted(claims: unknown, name: string, sources: readonly string[]): void {
  assert(isRecord(claims), 'Phala upstream claims are missing')
  const claim = claims[name]
  assert(isRecord(claim), `Phala upstream claim is missing: ${name}`)
  assert(claim.status === 'asserted' && typeof claim.source === 'string' && sources.includes(claim.source), `Phala upstream claim is not acceptable: ${name}`)
}

function bytesFromDataUri(value: string): Uint8Array {
  const match = /^data:[^,]*;base64,([A-Za-z0-9+/=]+)$/.exec(value)
  assert(match, 'Phala session evidence is not a base64 data URI')
  const binary = atob(match[1]!)
  return Uint8Array.from(binary, (char) => char.charCodeAt(0))
}

async function fetchJson(path: string, modelId: string, accessToken: string): Promise<unknown> {
  const response = await fetch(`${path}?model=${encodeURIComponent(modelId)}`, {
    cache: 'no-store',
    headers: { 'x-demo-access-token': accessToken },
  })
  const text = await response.text()
  if (!response.ok) throw new Error(`Phala evidence fetch failed (${response.status}): ${text.slice(0, 180)}`)
  return JSON.parse(text)
}

export interface PhalaReceiptVerification {
  receipt: CompletionReceipt
  cleartextResponseHashMatched: boolean
  upstreamClaims: unknown
}

export async function verifyPhalaCompletionReceipt(input: {
  receiptId: string
  policy: PhalaModelPolicy
  keyset: WorkloadKeyset
  plaintextRequestBody: string
  responseWireBody: string
  responseCleartextBody: string
  accessToken: string
}): Promise<PhalaReceiptVerification> {
  assert(/^rcpt-[0-9a-f]{24}$/.test(input.receiptId), 'Invalid Phala receipt id')
  const rawReceipt = await fetchJson(`/api/phala/receipts/${input.receiptId}`, input.policy.id, input.accessToken)
  assert(isRecord(rawReceipt), 'Invalid Phala receipt')
  const receipt = rawReceipt as Receipt
  assert(receipt.api_version === 'aci/1' && receipt.receipt_id === input.receiptId, 'Phala receipt identity mismatch')
  assert(receipt.model === input.policy.model, 'Phala receipt model mismatch')
  assert(receipt.endpoint === '/v1/chat/completions' && receipt.method === 'POST', 'Phala receipt endpoint mismatch')
  assert(Array.isArray(receipt.event_log) && receipt.event_log.length >= 4, 'Phala receipt event log is incomplete')
  receipt.event_log.forEach((entry, index) => assert(entry.seq === index, 'Phala receipt event sequence is invalid'))
  assert(receipt.event_log[0]?.type === 'request.received', 'Phala receipt does not begin with request.received')
  assert(receipt.signature.key_id === input.policy.receiptKeyId && receipt.signature.algo === input.policy.receiptAlgorithm, 'Phala receipt used an unapproved signing key')

  const signature = await verifyReceipt(receipt, input.keyset)
  assert(signature.ok, `Phala receipt signature failed: ${signature.checks.filter((check) => !check.ok).map((check) => check.name).join(', ')}`)
  assert(await checkRequestBodyHash(receipt, input.plaintextRequestBody), 'Phala receipt request hash mismatch')
  assert(await checkResponseWireHash(receipt, input.responseWireBody), 'Phala receipt response wire hash mismatch')
  // `cleartext_hash` covers the provider's exact upstream serialization. After
  // field-level E2EE decryption the browser has the same logical JSON but not the
  // original whitespace/key-order bytes, so expose this comparison as a signed
  // diagnostic rather than treating reserialization drift as a trust failure.
  const cleartextResponseHashMatched = await checkResponseCleartextHash(receipt, input.responseCleartextBody)

  const received = event(receipt, 'request.received')
  const forwarded = event(receipt, 'request.forwarded')
  if (received.body_hash !== forwarded.body_hash) event(receipt, 'transparency.request_modified')
  assertResponseTransparency(receipt)

  const upstream = event(receipt, 'upstream.verified')
  assert(upstream.required === true && upstream.result === 'verified', 'Phala upstream verification was not required and successful')
  assert(upstream.provider_type === input.policy.requiredUpstreamProviderType, `Unexpected Phala upstream verifier: ${String(upstream.provider_type)}`)
  assert(upstream.model_id === input.policy.model, 'Phala upstream model mismatch')
  assert(typeof upstream.url_origin === 'string' && upstream.url_origin.startsWith('https://'), 'Phala upstream origin is not HTTPS')
  assert(typeof upstream.session_id === 'string' && /^as_[0-9a-f]{64}$/.test(upstream.session_id), 'Phala upstream session id is invalid')
  claimAsserted(upstream.claims, 'tee_attested', ['hardware_proven'])
  claimAsserted(upstream.claims, 'gpu_attested', ['verifier_derived'])
  claimAsserted(upstream.claims, 'tcb_up_to_date', ['hardware_proven', 'verifier_derived'])

  const rawSession = await fetchJson(`/api/phala/sessions/${upstream.session_id}`, input.policy.id, input.accessToken)
  assert(isRecord(rawSession), 'Invalid Phala upstream session')
  const session = rawSession as SessionRecord & { api_version?: unknown; session_id?: unknown }
  assert(session.api_version === 'aci/1' && session.session_id === upstream.session_id, 'Phala session identity mismatch')
  assert(await computeSessionId(session) === upstream.session_id, 'Phala session content hash mismatch')
  assert(session.endpoint === upstream.url_origin && session.verifier_id === 'private-ai-verifier/phala-direct/v1', 'Phala session verifier or endpoint mismatch')
  assert(canonicalize(session.channel_binding as JcsValue) === canonicalize(upstream.channel_bindings as JcsValue), 'Phala session channel binding mismatch')
  assert(canonicalize(session.claims as JcsValue) === canonicalize(upstream.claims as JcsValue), 'Phala session claims mismatch')
  assert(session.evidence && typeof session.evidence === 'object', 'Phala session evidence commitment is missing')
  assert(typeof session.evidence.digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(session.evidence.digest), 'Phala session evidence digest is missing or invalid')
  assert(typeof session.evidence.data === 'string', 'Phala session evidence bytes are missing')
  assert(await sha256Prefixed(bytesFromDataUri(session.evidence.data)) === session.evidence.digest, 'Phala session evidence digest mismatch')

  const responseReturned = event(receipt, 'response.returned')
  return {
    cleartextResponseHashMatched,
    upstreamClaims: upstream.claims,
    receipt: {
      provider: 'phala-cloud',
      model: input.policy.model,
      requestHash: String(received.body_hash),
      responseHash: String(responseReturned.wire_hash ?? await hashBody(input.responseWireBody)),
      signer: `${receipt.workload_id}#${receipt.signature.key_id}`,
      signature: receipt.signature.value,
      signedText: new TextDecoder().decode(receiptSigningBytes(receipt)),
      verifiedAt: new Date().toISOString(),
      receiptId: receipt.receipt_id,
      workloadId: receipt.workload_id,
      workloadKeysetDigest: receipt.workload_keyset_digest,
      upstreamProviderType: String(upstream.provider_type),
      sessionId: String(upstream.session_id),
    },
  }
}
