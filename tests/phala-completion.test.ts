import { ed25519 } from '@noble/curves/ed25519.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { bytesToHex } from '../src/lib/encoding'
import { computeSessionId, hashBody, receiptSigningBytes, type JcsValue, type ReceiptEnvelope, type ReceiptPayload, type WorkloadKeyset } from '../src/lib/phala-aci'
import { auditSession, requireVerifiedUpstream, verifyPhalaCompletionReceipt } from '../src/lib/phala-completion'
import { getModelPolicy, isPhalaPolicy, type PhalaModelPolicy } from '../src/lib/policy'

function livePolicy(): PhalaModelPolicy {
  const policy = getModelPolicy('phala-gpt-oss-20b')
  if (!isPhalaPolicy(policy)) throw new Error('Expected the Phala policy')
  return policy
}

const POLICY = livePolicy()
const RECEIPT_SEED = new Uint8Array(32).fill(0x02)
const RECEIPT_PUBLIC = bytesToHex(ed25519.getPublicKey(RECEIPT_SEED))
const KEYSET_DIGEST = 'sha256:' + '4f'.repeat(32)
const RECEIPT_ID = 'rcpt-0123456789abcdef01234567'
const ACCESS = 'demo-access-token-with-twenty-plus-chars'
const SERVED_AT = 1_788_316_500

const KEYSET: WorkloadKeyset = {
  subject: null,
  not_after: 1_790_000_000,
  receipt_signing_keys: [{ key_id: POLICY.receiptKeyId, algo: 'ed25519', public_key: RECEIPT_PUBLIC }],
  e2ee_public_keys: [],
}

/** Shaped like a live phala-direct session record; the id is its content address. */
function sessionRecord(overrides: Record<string, JcsValue> = {}): Record<string, JcsValue> {
  return {
    api_version: 'aci/1',
    upstream_name: 'phala-23',
    endpoint: 'https://gpt-oss-20b.use1.phala.com',
    verifier_id: POLICY.requiredUpstreamVerifierId,
    established_at: SERVED_AT - 300,
    expires_at: SERVED_AT + 3300,
    identity: { signing_address: '0x' + 'af'.repeat(20) },
    channel_binding: [{ type: 'tls_spki_sha256', origin: 'https://gpt-oss-20b.use1.phala.com', spki_sha256: '1e'.repeat(32) }],
    claims: {
      tee_attested: { status: 'asserted', source: 'hardware_proven', reason: 'quote verified' },
      gpu_attested: { status: 'asserted', source: 'verifier_derived', reason: 'NRAS verdict nonce-bound' },
      tcb_up_to_date: { status: 'asserted', source: 'hardware_proven', reason: 'UpToDate' },
      os_known_good: { status: 'asserted', source: 'verifier_derived' },
      serving_software_known_good: { status: 'unknown' },
      model_weights_provenance: { status: 'unknown' },
      extra: { tcb_status: 'UpToDate', gpu_arch: 'HOPPER' },
    },
    evidence: { digest: 'sha256:80d70e44d0ae1e829fd5f37c3ee4a60dfbea8d3aa18407ea3f34cf7ec91da34d', data: 'data:application/json;base64,ZXhhbXBsZS1ldmlkZW5jZQ==' },
    ...overrides,
  }
}

const REQUEST_BODY = JSON.stringify({ model: POLICY.model, messages: [{ role: 'user', content: 'hi' }], stream: false, max_tokens: 512, provider: { aci_verified: true } })
const FORWARDED_BODY = JSON.stringify({ model: POLICY.model, messages: [{ role: 'user', content: 'hi' }], stream: false, max_tokens: 512 })
const RESPONSE_BODY = '{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"abcd"}}],"model":"openai/gpt-oss-20b"}'

function receiptPayload(sessionId: string, overrides: Partial<ReceiptPayload> = {}): ReceiptPayload {
  return {
    api_version: 'aci/1',
    receipt_id: RECEIPT_ID,
    chat_id: 'chatcmpl-1',
    model: POLICY.model,
    workload_keyset_digest: KEYSET_DIGEST,
    endpoint: '/v1/chat/completions',
    method: 'POST',
    served_at: SERVED_AT,
    event_log: [
      { type: 'request.received', body_hash: hashBody(REQUEST_BODY) },
      { type: 'request.forwarded', body_hash: hashBody(FORWARDED_BODY) },
      { type: 'upstream.verified', result: 'verified', required: true, model_id: POLICY.model, session_id: sessionId },
      { type: 'routing.decision', upstream_name: 'phala-23' },
      { type: 'response.returned', body_hash: hashBody(RESPONSE_BODY) },
    ],
    key_id: POLICY.receiptKeyId,
    ...overrides,
  }
}

function sign(payload: ReceiptPayload, seed = RECEIPT_SEED): ReceiptEnvelope {
  const unsigned: ReceiptEnvelope = { ...payload, signature: '' }
  return { ...unsigned, signature: bytesToHex(ed25519.sign(receiptSigningBytes(unsigned), seed)) }
}

describe('requireVerifiedUpstream', () => {
  const payload = (events: ReceiptPayload['event_log']) => receiptPayload('ab'.repeat(32), { event_log: events })
  const verified = { type: 'upstream.verified', result: 'verified', required: true, model_id: POLICY.model, session_id: 'ab'.repeat(32) }

  it('accepts one required, verified event alongside a failed attempt', () => {
    const failed = { type: 'upstream.verified', result: 'failed', required: true, model_id: POLICY.model, reason: 'timeout' }
    expect(requireVerifiedUpstream(payload([failed, verified]), POLICY.model)).toEqual({ sessionId: 'ab'.repeat(32) })
  })

  it('refuses best-effort, failed, duplicated, mis-modelled, and mis-cited events', () => {
    expect(() => requireVerifiedUpstream(payload([]), POLICY.model)).toThrow('records no upstream verification')
    expect(() => requireVerifiedUpstream(payload([{ ...verified, required: false }]), POLICY.model)).toThrow('was not required')
    expect(() => requireVerifiedUpstream(payload([{ ...verified, result: 'failed', reason: 'x' }]), POLICY.model)).toThrow('exactly one verified upstream')
    expect(() => requireVerifiedUpstream(payload([verified, verified]), POLICY.model)).toThrow('exactly one verified upstream')
    expect(() => requireVerifiedUpstream(payload([{ ...verified, model_id: 'openai/gpt-oss-120b' }]), POLICY.model)).toThrow('upstream model mismatch')
    expect(() => requireVerifiedUpstream(payload([{ ...verified, session_id: `as_${'ab'.repeat(32)}` }]), POLICY.model)).toThrow('session id is invalid')
    expect(() => requireVerifiedUpstream(payload([{ ...verified, session_id: undefined }]), POLICY.model)).toThrow('session id is invalid')
  })
})

describe('auditSession', () => {
  const record = sessionRecord()
  const id = computeSessionId(record)

  it('accepts a record that hashes to its id and meets the policy', () => {
    expect(auditSession(record, id, SERVED_AT, POLICY)).toBe(record)
  })

  it('refuses a record that does not hash to the cited id', () => {
    expect(() => auditSession(sessionRecord({ upstream_name: 'phala-24' }), id, SERVED_AT, POLICY)).toThrow('content hash mismatch')
    expect(() => auditSession(record, 'ab'.repeat(32), SERVED_AT, POLICY)).toThrow('content hash mismatch')
  })

  const denials: Array<[string, Record<string, JcsValue> | ((policy: PhalaModelPolicy) => PhalaModelPolicy), string, number?]> = [
    ['a foreign api_version', { api_version: 'aci/0' }, 'api_version is not aci/1'],
    ['another verifier', (policy) => ({ ...policy, requiredUpstreamVerifierId: 'private-ai-verifier/other/v1' }), 'Unexpected Phala upstream verifier'],
    ['a plaintext upstream origin', { endpoint: 'http://gpt-oss-20b.use1.phala.com', channel_binding: [{ type: 'tls_spki_sha256', origin: 'http://gpt-oss-20b.use1.phala.com', spki_sha256: '1e'.repeat(32) }] }, 'not HTTPS'],
    ['a channel binding for another origin', { channel_binding: [{ type: 'tls_spki_sha256', origin: 'https://other.example', spki_sha256: '1e'.repeat(32) }] }, 'not TLS-pinned'],
    ['a channel binding of an unenforceable type', { channel_binding: [{ type: 'e2ee_public_key_sha256', origin: 'https://gpt-oss-20b.use1.phala.com', spki_sha256: '1e'.repeat(32) }] }, 'not TLS-pinned'],
    ['a TEE claim that is only provider-asserted', { claims: { ...(record.claims as object), tee_attested: { status: 'asserted', source: 'provider_asserted' } } }, 'not acceptable: tee_attested'],
    ['a GPU claim that is unknown', { claims: { ...(record.claims as object), gpu_attested: { status: 'unknown' } } }, 'not acceptable: gpu_attested'],
    ['a refuted TCB claim', { claims: { ...(record.claims as object), tcb_up_to_date: { status: 'refuted', source: 'hardware_proven' } } }, 'not acceptable: tcb_up_to_date'],
    ['a missing TCB claim', { claims: Object.fromEntries(Object.entries(record.claims as object).filter(([name]) => name !== 'tcb_up_to_date')) }, 'claim is missing: tcb_up_to_date'],
    ['a receipt served before the session', {}, 'outside the session validity window', SERVED_AT - 301],
    ['a receipt served after the session', {}, 'outside the session validity window', SERVED_AT + 3301],
    ['evidence that does not hash to its digest', { evidence: { digest: 'sha256:' + '00'.repeat(32), data: 'data:application/json;base64,ZXhhbXBsZS1ldmlkZW5jZQ==' } }, 'does not hash to its digest'],
    ['evidence without data', { evidence: { digest: 'sha256:80d70e44d0ae1e829fd5f37c3ee4a60dfbea8d3aa18407ea3f34cf7ec91da34d' } }, 'does not hash to its digest'],
    ['an evidence digest that is not sha256', { evidence: { digest: 'sha512:' + '00'.repeat(64), data: 'data:application/json;base64,ZXhhbXBsZS1ldmlkZW5jZQ==' } }, 'digest is missing or invalid'],
  ]
  for (const [label, change, message, servedAt = SERVED_AT] of denials) {
    it(`refuses ${label}`, () => {
      const policy = typeof change === 'function' ? change(POLICY) : POLICY
      const mutated = typeof change === 'function' ? record : sessionRecord(change)
      expect(() => auditSession(mutated, computeSessionId(mutated), servedAt, policy)).toThrow(message)
    })
  }

  it('refuses a prototype-polluting record', () => {
    expect(() => auditSession(JSON.parse('{"__proto__":{"x":1},"api_version":"aci/1"}'), id, SERVED_AT, POLICY)).toThrow('Unsafe response key')
  })
})

describe('verifyPhalaCompletionReceipt', () => {
  afterEach(() => vi.unstubAllGlobals())

  function serve(documents: Record<string, unknown>, calls: Array<{ path: string; headers: Headers }> = []) {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      calls.push({ path, headers: new Headers(init?.headers) })
      const document = documents[path.split('?')[0]!]
      if (document === undefined) return new Response(JSON.stringify({ error: 'not found' }), { status: 404 })
      return new Response(JSON.stringify(document), { status: 200, headers: { 'content-type': 'application/json' } })
    }))
    return calls
  }

  function input(overrides: Partial<Parameters<typeof verifyPhalaCompletionReceipt>[0]> = {}) {
    return {
      receiptId: RECEIPT_ID,
      policy: POLICY,
      keyset: KEYSET,
      workloadKeysetDigest: KEYSET_DIGEST,
      plaintextRequestBody: REQUEST_BODY,
      responseWireBody: RESPONSE_BODY,
      accessToken: ACCESS,
      ...overrides,
    }
  }

  const session = sessionRecord()
  const sessionId = computeSessionId(session)
  const receipt = sign(receiptPayload(sessionId))
  const routes = () => ({
    [`/api/phala/receipts/${RECEIPT_ID}`]: receipt,
    [`/api/phala/sessions/${sessionId}`]: session,
  })

  it('verifies the receipt, audits the cited session, and reports what the receipt binds', async () => {
    const calls = serve(routes())
    const verified = await verifyPhalaCompletionReceipt(input())
    expect(verified).toMatchObject({
      provider: 'phala-cloud',
      model: POLICY.model,
      requestHash: hashBody(REQUEST_BODY),
      responseHash: hashBody(RESPONSE_BODY),
      signer: `${KEYSET_DIGEST}#${POLICY.receiptKeyId}`,
      signature: receipt.signature,
      receiptId: RECEIPT_ID,
      workloadKeysetDigest: KEYSET_DIGEST,
      sessionId,
      upstreamEndpoint: 'https://gpt-oss-20b.use1.phala.com',
    })
    expect(verified.signedText).toBe(new TextDecoder().decode(receiptSigningBytes(receipt)))
    expect(calls.map((call) => call.path)).toEqual([
      `/api/phala/receipts/${RECEIPT_ID}?model=${POLICY.id}`,
      `/api/phala/sessions/${sessionId}?model=${POLICY.id}`,
    ])
    for (const call of calls) expect(call.headers.get('x-demo-access-token')).toBe(ACCESS)
  })

  it('refuses receipt ids outside the gateway format before any fetch', async () => {
    const calls = serve(routes())
    await expect(verifyPhalaCompletionReceipt(input({ receiptId: 'rcpt-../sessions' }))).rejects.toThrow('Invalid Phala receipt id')
    expect(calls).toHaveLength(0)
  })

  it('refuses a receipt signed by an unapproved or foreign key', async () => {
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { key_id: 'receipt-2' })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('unapproved signing key')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId), new Uint8Array(32).fill(0x09)) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('receipt verification failed: signature')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: { ...receipt, signature: undefined } })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('receipt is unsigned')
  })

  it('refuses a receipt bound to another keyset or another exchange', async () => {
    serve(routes())
    await expect(verifyPhalaCompletionReceipt(input({ workloadKeysetDigest: 'sha256:' + '00'.repeat(32) }))).rejects.toThrow('receipt verification failed: workload_keyset_digest')
    await expect(verifyPhalaCompletionReceipt(input({ plaintextRequestBody: REQUEST_BODY.replace('"hi"', '"hi!"') }))).rejects.toThrow('request hash mismatch')
    await expect(verifyPhalaCompletionReceipt(input({ responseWireBody: `${RESPONSE_BODY}\n` }))).rejects.toThrow('response hash mismatch')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { receipt_id: 'rcpt-fedcba9876543210fedcba98' })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('receipt identity mismatch')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { model: 'openai/gpt-oss-120b' })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('receipt model mismatch')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { endpoint: '/v1/completions' })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('receipt endpoint mismatch')
  })

  it('refuses a receipt whose event log is malformed or records no forward', async () => {
    const events = receiptPayload(sessionId).event_log
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { event_log: [events[1]!, events[0]!, ...events.slice(2)] })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('does not begin with request.received')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { event_log: events.filter((event) => event.type !== 'request.forwarded') })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('missing request.forwarded')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { event_log: events.map((event) => (event.type === 'upstream.verified' ? { ...event, required: false } : event)) })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('was not required')
  })

  it('refuses a cited session that is missing, altered, or does not cover served_at', async () => {
    serve({ [`/api/phala/receipts/${RECEIPT_ID}`]: receipt })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('Request failed (404)')
    serve({ ...routes(), [`/api/phala/sessions/${sessionId}`]: { ...session, upstream_name: 'phala-24' } })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('session content hash mismatch')
    serve({ ...routes(), [`/api/phala/receipts/${RECEIPT_ID}`]: sign(receiptPayload(sessionId, { served_at: SERVED_AT + 4000 })) })
    await expect(verifyPhalaCompletionReceipt(input())).rejects.toThrow('outside the session validity window')
  })
})
