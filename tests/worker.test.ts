import { describe, expect, it, vi } from 'vitest'
import { handleApiRequest } from '../worker/index'
import { POLICY } from '../src/lib/policy'

const ORIGIN = `https://${POLICY.endpointLabel}`
const CIPHERTEXT = 'a'.repeat(160)
const KEY = 'b'.repeat(64)

function makeEnv(apiKey?: string): Env {
  return {
    ASSETS: { fetch: vi.fn() } as unknown as Fetcher,
    ...(apiKey ? { NEAR_AI_API_KEY: apiKey } : {}),
  } as Env
}

function encryptedBody(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    model: POLICY.model,
    messages: [{ role: 'user', content: CIPHERTEXT }],
    max_tokens: 256,
    stream: false,
    ...overrides,
  })
}

function chatRequest(body = encryptedBody()) {
  return new Request('https://app.test/api/chat', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-client-pub-key': KEY,
      'x-model-pub-key': KEY,
      'x-signing-algo': 'ed25519',
      'x-encryption-version': '2',
    },
    body,
  })
}

describe('fixed ciphertext-only Worker relay', () => {
  it('fails closed when the provider key is absent', async () => {
    const upstream = vi.fn()
    const response = await handleApiRequest(chatRequest(), makeEnv(), upstream)
    expect(response.status).toBe(503)
    expect(await response.json()).toMatchObject({ code: 'missing_api_key' })
    expect(upstream).not.toHaveBeenCalled()
  })

  it('forwards exact encrypted bytes to only the compiled origin', async () => {
    const body = encryptedBody()
    let captured: { url: string; init?: RequestInit } | undefined
    const upstream = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      captured = { url: String(input), init }
      return new Response('{"id":"chat-123","choices":[]}', {
        status: 200,
        headers: { 'content-type': 'application/json', 'x-request-id': 'opaque-123' },
      })
    })
    const response = await handleApiRequest(chatRequest(body), makeEnv('server-secret'), upstream)
    expect(response.status).toBe(200)
    expect(captured?.url).toBe(`${ORIGIN}/v1/chat/completions`)
    const headers = new Headers(captured?.init?.headers)
    expect(headers.get('authorization')).toBe('Bearer server-secret')
    expect(headers.get('x-no-aliasing')).toBe('true')
    expect(headers.get('x-client-pub-key')).toBe(KEY)
    expect(await new Response(captured?.init?.body).text()).toBe(body)
  })

  it('rejects plaintext, extra fields, model substitution, and multiple messages', async () => {
    const upstream = vi.fn()
    const plaintext = JSON.stringify({ model: POLICY.model, messages: [{ role: 'user', content: 'plaintext' }], max_tokens: 256, stream: false })
    const extra = encryptedBody({ user: 'plaintext identifier' })
    const substituted = encryptedBody({ model: 'evil/model' })
    const multiple = encryptedBody({ messages: [{ role: 'user', content: CIPHERTEXT }, { role: 'user', content: CIPHERTEXT }] })
    for (const body of [plaintext, extra, substituted, multiple]) {
      const response = await handleApiRequest(chatRequest(body), makeEnv('secret'), upstream)
      expect(response.status).toBe(400)
    }
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
      cancel() {
        cancelled = true
      },
    })
    const request = new Request('https://app.test/api/chat', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-client-pub-key': KEY,
        'x-model-pub-key': KEY,
        'x-signing-algo': 'ed25519',
        'x-encryption-version': '2',
      },
      body: stream,
      duplex: 'half',
    } as RequestInit & { duplex: 'half' })
    const upstream = vi.fn()
    const response = await handleApiRequest(request, makeEnv('secret'), upstream)
    expect(response.status).toBe(413)
    expect(cancelled).toBe(true)
    expect(produced).toBeLessThan(128 * 1024)
    expect(upstream).not.toHaveBeenCalled()
  })

  it('pins attestation and signatures to the same fixed origin', async () => {
    const upstream = vi.fn(async () => new Response('{}', { status: 200 }))
    const nonce = 'c'.repeat(64)
    const attestation = await handleApiRequest(new Request(`https://app.test/api/attestation?nonce=${nonce}`), makeEnv(), upstream)
    const signature = await handleApiRequest(new Request('https://app.test/api/signature/chat_123456'), makeEnv('secret'), upstream)
    expect(attestation.status).toBe(200)
    expect(signature.status).toBe(200)
    expect(upstream).toHaveBeenNthCalledWith(1, `${ORIGIN}/v1/attestation/report?signing_algo=ed25519&nonce=${nonce}`, expect.objectContaining({ redirect: 'manual' }))
    expect(upstream).toHaveBeenNthCalledWith(2, `${ORIGIN}/v1/signature/chat_123456?signing_algo=ed25519`, expect.objectContaining({ redirect: 'manual' }))
  })

  it('rejects malformed challenges and arbitrary GPU verifier payloads', async () => {
    const upstream = vi.fn()
    const badNonce = await handleApiRequest(new Request('https://app.test/api/attestation?nonce=short'), makeEnv(), upstream)
    const badNras = await handleApiRequest(new Request('https://app.test/api/nras', {
      method: 'POST',
      body: JSON.stringify({ url: 'https://attacker.example' }),
    }), makeEnv(), upstream)
    expect(badNonce.status).toBe(400)
    expect(badNras.status).toBe(400)
    expect(upstream).not.toHaveBeenCalled()
  })
})
