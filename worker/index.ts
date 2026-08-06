import { POLICY } from '../src/lib/policy'

const MAX_CHAT_BYTES = 64 * 1024
const MAX_NRAS_BYTES = 256 * 1024
const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_BYTES = /^[0-9a-f]+$/i
const MAX_CIPHERTEXT_HEX_CHARS = 16_384
const CHAT_ID = /^[a-zA-Z0-9_-]{8,128}$/
const EXACT_CHAT_KEYS = new Set(['model', 'messages', 'max_tokens', 'stream'])
const EXACT_MESSAGE_KEYS = new Set(['role', 'content'])

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

function jsonResponse(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  })
}

function upstreamUrl(path: string, query = ''): string {
  return `https://${POLICY.endpointLabel}${path}${query}`
}

async function boundedBody(request: Request, limit: number): Promise<ArrayBuffer> {
  const contentLength = request.headers.get('content-length')
  if (contentLength !== null) {
    const declared = Number(contentLength)
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > limit) {
      throw new RangeError('request_too_large')
    }
  }

  if (!request.body) return new ArrayBuffer(0)

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > limit) {
        await reader.cancel().catch(() => undefined)
        throw new RangeError('request_too_large')
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }

  const body = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return body.buffer
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key))
}

function validCiphertext(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 146
    && value.length <= MAX_CIPHERTEXT_HEX_CHARS
    && value.length % 2 === 0
    && HEX_BYTES.test(value)
}

function validEncryptedPrompt(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const body = value as Record<string, unknown>
  if (!hasOnlyKeys(body, EXACT_CHAT_KEYS)) return false
  if (body.model !== POLICY.model || body.stream !== false || body.max_tokens !== 256) return false
  if (!Array.isArray(body.messages) || body.messages.length !== 1) return false
  const message = body.messages[0]
  if (!message || typeof message !== 'object' || Array.isArray(message)) return false
  const item = message as Record<string, unknown>
  return hasOnlyKeys(item, EXACT_MESSAGE_KEYS) && item.role === 'user' && validCiphertext(item.content)
}

function requireApiKey(env: Env): string | Response {
  if (!env.NEAR_AI_API_KEY) return jsonResponse({ error: 'NEAR AI Cloud API key is not configured', code: 'missing_api_key' }, 503)
  return env.NEAR_AI_API_KEY
}

async function proxyAttestation(request: Request, upstreamFetch: FetchLike): Promise<Response> {
  if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405)
  const nonce = new URL(request.url).searchParams.get('nonce') ?? ''
  if (!HEX_32.test(nonce)) return jsonResponse({ error: 'nonce must be 32 bytes of hex' }, 400)
  const upstream = await upstreamFetch(
    upstreamUrl('/v1/attestation/report', `?signing_algo=ed25519&nonce=${nonce}`),
    { headers: { accept: 'application/json' }, redirect: 'manual' },
  )
  if (!upstream.ok) return jsonResponse({ error: 'Attestation provider unavailable', code: 'upstream_attestation_error' }, 502)
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

async function proxyChat(request: Request, env: Env, upstreamFetch: FetchLike): Promise<Response> {
  if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405)
  const apiKey = requireApiKey(env)
  if (apiKey instanceof Response) return apiKey
  const clientKey = request.headers.get('x-client-pub-key') ?? ''
  const modelKey = request.headers.get('x-model-pub-key') ?? ''
  if (!HEX_32.test(clientKey) || !HEX_32.test(modelKey)) return jsonResponse({ error: 'Invalid encryption key headers' }, 400)
  if (request.headers.get('x-signing-algo') !== 'ed25519' || request.headers.get('x-encryption-version') !== '2') {
    return jsonResponse({ error: 'Only NEAR Ed25519 E2EE v2 is accepted' }, 400)
  }

  let body: ArrayBuffer
  try {
    body = await boundedBody(request, MAX_CHAT_BYTES)
  } catch {
    return jsonResponse({ error: 'Chat request is too large' }, 413)
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(body))
  } catch {
    return jsonResponse({ error: 'Malformed JSON' }, 400)
  }
  if (!validEncryptedPrompt(parsed)) return jsonResponse({ error: 'Only the pinned encrypted prompt shape is accepted' }, 400)

  const upstream = await upstreamFetch(upstreamUrl('/v1/chat/completions'), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'accept-encoding': 'identity',
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      'x-client-pub-key': clientKey,
      'x-encryption-version': '2',
      'x-model-pub-key': modelKey,
      'x-no-aliasing': 'true',
      'x-signing-algo': 'ed25519',
    },
    body,
    redirect: 'manual',
  })
  if (!upstream.ok) return jsonResponse({ error: `Confidential model returned HTTP ${upstream.status}`, code: 'upstream_chat_error' }, upstream.status)
  const headers = new Headers({
    'content-type': upstream.headers.get('content-type') ?? 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  const requestId = upstream.headers.get('x-request-id')
  if (requestId) headers.set('x-request-id', requestId)
  return new Response(upstream.body, { status: upstream.status, headers })
}

async function proxySignature(request: Request, env: Env, upstreamFetch: FetchLike, chatId: string): Promise<Response> {
  if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405)
  const apiKey = requireApiKey(env)
  if (apiKey instanceof Response) return apiKey
  if (!CHAT_ID.test(chatId)) return jsonResponse({ error: 'Invalid chat id' }, 400)
  const upstream = await upstreamFetch(upstreamUrl(`/v1/signature/${chatId}`, '?signing_algo=ed25519'), {
    headers: { accept: 'application/json', authorization: `Bearer ${apiKey}` },
    redirect: 'manual',
  })
  if (upstream.status === 404) return jsonResponse({ error: 'Signature not found' }, 404)
  if (!upstream.ok) return jsonResponse({ error: 'Signature provider unavailable', code: 'upstream_signature_error' }, 502)
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

async function proxyNras(request: Request, upstreamFetch: FetchLike): Promise<Response> {
  if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405)
  let body: ArrayBuffer
  try {
    body = await boundedBody(request, MAX_NRAS_BYTES)
  } catch {
    return jsonResponse({ error: 'GPU evidence is too large' }, 413)
  }
  try {
    const payload = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>
    if (payload.arch !== POLICY.gpuArchitecture || !HEX_32.test(String(payload.nonce ?? '')) || !Array.isArray(payload.evidence_list)) {
      return jsonResponse({ error: 'Malformed GPU evidence' }, 400)
    }
    if (payload.evidence_list.length !== POLICY.gpuCount) return jsonResponse({ error: 'Unexpected GPU evidence count' }, 400)
  } catch {
    return jsonResponse({ error: 'Malformed GPU evidence JSON' }, 400)
  }
  const upstream = await upstreamFetch('https://nras.attestation.nvidia.com/v3/attest/gpu', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body,
    redirect: 'manual',
  })
  if (!upstream.ok) return jsonResponse({ error: 'NVIDIA attestation service unavailable', code: 'upstream_nras_error' }, 502)
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

export async function handleApiRequest(request: Request, env: Env, upstreamFetch: FetchLike = fetch): Promise<Response> {
  const url = new URL(request.url)
  if (url.pathname === '/api/attestation') return proxyAttestation(request, upstreamFetch)
  if (url.pathname === '/api/chat') return proxyChat(request, env, upstreamFetch)
  if (url.pathname === '/api/nras') return proxyNras(request, upstreamFetch)
  if (url.pathname.startsWith('/api/signature/')) {
    return proxySignature(request, env, upstreamFetch, url.pathname.slice('/api/signature/'.length))
  }
  return jsonResponse({ error: 'Not found' }, 404)
}

export default {
  async fetch(request, env): Promise<Response> {
    try {
      const url = new URL(request.url)
      if (url.pathname.startsWith('/api/')) return await handleApiRequest(request, env)
      return env.ASSETS.fetch(request)
    } catch (error) {
      console.error(JSON.stringify({
        message: 'request_failed',
        path: new URL(request.url).pathname,
        error: error instanceof Error ? error.message : 'unknown error',
      }))
      return jsonResponse({ error: 'Internal request failure', code: 'internal_error' }, 500)
    }
  },
} satisfies ExportedHandler<Env>
