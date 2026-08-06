import { describe, expect, it, vi } from 'vitest'
import { handleApiRequest } from '../worker/index'
import { getModelPolicy } from '../src/lib/policy'

const NEAR = getModelPolicy('deepseek-v4-flash')
const PHALA = getModelPolicy('phala-gpt-oss-20b')
const CIPHERTEXT = 'a'.repeat(160)
const KEY = 'b'.repeat(64)
const ACCESS = 'correct-owner-access-token-2026'

function makeEnv(options: { near?: string | null; phala?: string | null; access?: string | null } = {}): Env {
  const near = options.near === undefined ? 'near-secret' : options.near
  const phala = options.phala === undefined ? 'phala-secret' : options.phala
  const access = options.access === undefined ? ACCESS : options.access
  return {
    ASSETS: { fetch: vi.fn() } as unknown as Fetcher,
    ...(near ? { NEAR_AI_API_KEY: near } : {}),
    ...(phala ? { PHALA_API_KEY: phala } : {}),
    ...(access ? { DEMO_ACCESS_TOKEN: access } : {}),
  } as Env
}

function nearBody(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({ model: NEAR.model, messages: [{ role: 'user', content: CIPHERTEXT }], max_tokens: 256, stream: false, ...overrides })
}

function phalaBody(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({ model: PHALA.model, messages: [{ role: 'user', content: CIPHERTEXT }], max_tokens: 512, stream: false, provider: { aci_verified: true }, ...overrides })
}

function nearChatRequest(body = nearBody(), access = ACCESS) {
  return new Request(`https://app.test/api/chat?model=${NEAR.id}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-demo-access-token': access,
      'x-client-pub-key': KEY,
      'x-model-pub-key': KEY,
      'x-signing-algo': 'ed25519',
      'x-encryption-version': '2',
    },
    body,
  })
}

function phalaChatRequest(body = phalaBody(), access = ACCESS) {
  return new Request(`https://app.test/api/chat?model=${PHALA.id}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-demo-access-token': access,
      'x-client-pub-key': KEY,
      'x-model-pub-key': KEY,
      'x-e2ee-version': '2',
      'x-e2ee-nonce': 'c'.repeat(64),
      'x-e2ee-timestamp': String(Math.floor(Date.now() / 1000)),
    },
    body,
  })
}

describe('gated ciphertext-only Worker relay', () => {
  it('requires the owner token before any provider-billed route', async () => {
    const upstream = vi.fn()
    const missingGate = await handleApiRequest(nearChatRequest(), makeEnv({ access: null }), upstream)
    const wrongToken = await handleApiRequest(nearChatRequest(undefined, 'wrong-token-that-is-long-enough'), makeEnv(), upstream)
    const accessCheck = await handleApiRequest(new Request('https://app.test/api/access', {
      method: 'POST', headers: { 'x-demo-access-token': ACCESS },
    }), makeEnv(), upstream)
    expect(missingGate.status).toBe(503)
    expect(wrongToken.status).toBe(401)
    expect(accessCheck.status).toBe(204)
    expect(upstream).not.toHaveBeenCalled()
  })

  it('gates every provider-billed completion evidence route', async () => {
    const upstream = vi.fn()
    const paths = [
      `/api/signature/chat-12345678?model=${NEAR.id}`,
      `/api/phala/receipts/rcpt-0123456789abcdef01234567?model=${PHALA.id}`,
      `/api/phala/sessions/as_${'a'.repeat(64)}?model=${PHALA.id}`,
    ]
    for (const path of paths) {
      const response = await handleApiRequest(new Request(`https://app.test${path}`), makeEnv(), upstream)
      expect(response.status).toBe(401)
    }
    expect(upstream).not.toHaveBeenCalled()
  })

  it('fails closed when the selected provider key is absent', async () => {
    const upstream = vi.fn()
    const nearResponse = await handleApiRequest(nearChatRequest(), makeEnv({ near: null }), upstream)
    const phalaResponse = await handleApiRequest(phalaChatRequest(), makeEnv({ phala: null }), upstream)
    expect(nearResponse.status).toBe(503)
    expect(phalaResponse.status).toBe(503)
    expect(upstream).not.toHaveBeenCalled()
  })

  it('pins and forwards the exact NEAR encrypted request', async () => {
    const body = nearBody()
    let captured: { url: string; init?: RequestInit } | undefined
    const upstream = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      captured = { url: String(input), init }
      return new Response('{"id":"chat-123","choices":[]}', { status: 200, headers: { 'content-type': 'application/json' } })
    })
    const response = await handleApiRequest(nearChatRequest(body), makeEnv(), upstream)
    expect(response.status).toBe(200)
    expect(captured?.url).toBe(`https://${NEAR.endpointLabel}/v1/chat/completions`)
    const headers = new Headers(captured?.init?.headers)
    expect(headers.get('authorization')).toBe('Bearer near-secret')
    expect(headers.get('x-no-aliasing')).toBe('true')
    expect(headers.has('x-demo-access-token')).toBe(false)
    expect(await new Response(captured?.init?.body).text()).toBe(body)
  })

  it('pins the Phala origin and requires encrypted-response evidence', async () => {
    const upstream = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response('{"id":"chat-123","choices":[]}', {
      status: 200,
      headers: { 'content-type': 'application/json', 'x-e2ee-applied': 'true', 'x-e2ee-version': '2', 'x-receipt-id': 'rcpt-0123456789abcdef01234567' },
    }))
    const response = await handleApiRequest(phalaChatRequest(), makeEnv(), upstream)
    expect(response.status).toBe(200)
    expect(String(upstream.mock.calls[0]?.[0])).toBe(`https://${PHALA.endpointLabel}/v1/chat/completions`)
    const headers = new Headers(upstream.mock.calls[0]?.[1]?.headers)
    expect(headers.get('authorization')).toBe('Bearer phala-secret')
    expect(headers.get('x-e2ee-version')).toBe('2')
    expect(headers.has('x-demo-access-token')).toBe(false)
    expect(response.headers.get('x-receipt-id')).toBe('rcpt-0123456789abcdef01234567')
  })

  it('rejects plaintext, extra fields, model substitution, and multiple messages', async () => {
    const upstream = vi.fn()
    const bodies = [
      JSON.stringify({ model: NEAR.model, messages: [{ role: 'user', content: 'plaintext' }], max_tokens: 256, stream: false }),
      nearBody({ user: 'plaintext identifier' }),
      nearBody({ model: 'evil/model' }),
      nearBody({ messages: [{ role: 'user', content: CIPHERTEXT }, { role: 'user', content: CIPHERTEXT }] }),
    ]
    for (const body of bodies) expect((await handleApiRequest(nearChatRequest(body), makeEnv(), upstream)).status).toBe(400)
    expect(upstream).not.toHaveBeenCalled()
  })

  it('cancels an undeclared streaming body as soon as it crosses the limit', async () => {
    let produced = 0
    let cancelled = false
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = new Uint8Array(8 * 1024)
        produced += chunk.byteLength
        controller.enqueue(chunk)
        if (produced >= 1024 * 1024) controller.close()
      },
      cancel() { cancelled = true },
    })
    const request = new Request(`https://app.test/api/chat?model=${NEAR.id}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-demo-access-token': ACCESS,
        'x-client-pub-key': KEY,
        'x-model-pub-key': KEY,
        'x-signing-algo': 'ed25519',
        'x-encryption-version': '2',
      },
      body: stream,
      duplex: 'half',
    } as RequestInit & { duplex: 'half' })
    const upstream = vi.fn()
    const response = await handleApiRequest(request, makeEnv(), upstream)
    expect(response.status).toBe(413)
    expect(cancelled).toBe(true)
    expect(produced).toBeLessThan(128 * 1024)
    expect(upstream).not.toHaveBeenCalled()
  })

  it('pins attestation to one compiled origin per reviewed model', async () => {
    const upstream = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response('{}', { status: 200 }))
    const nonce = 'd'.repeat(64)
    for (const policy of [NEAR, PHALA]) {
      const response = await handleApiRequest(new Request(`https://app.test/api/attestation?model=${policy.id}&nonce=${nonce}`), makeEnv(), upstream)
      expect(response.status).toBe(200)
    }
    expect(String(upstream.mock.calls[0]?.[0])).toBe(`https://${NEAR.endpointLabel}/v1/attestation/report?signing_algo=ed25519&nonce=${nonce}`)
    expect(String(upstream.mock.calls[1]?.[0])).toBe(`https://${PHALA.endpointLabel}/v1/aci/attestation?nonce=${nonce}`)
  })

  it('rejects unapproved models, malformed challenges, and arbitrary GPU verifier payloads', async () => {
    const upstream = vi.fn()
    const unknown = await handleApiRequest(new Request(`https://app.test/api/attestation?model=evil&nonce=${'e'.repeat(64)}`), makeEnv(), upstream)
    const badNonce = await handleApiRequest(new Request(`https://app.test/api/attestation?model=${NEAR.id}&nonce=short`), makeEnv(), upstream)
    const badNras = await handleApiRequest(new Request('https://app.test/api/nras', { method: 'POST', body: JSON.stringify({ url: 'https://attacker.example' }) }), makeEnv(), upstream)
    expect(unknown.status).toBe(400)
    expect(badNonce.status).toBe(400)
    expect(badNras.status).toBe(400)
    expect(upstream).not.toHaveBeenCalled()
  })
})
