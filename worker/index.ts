import { isRecord } from '../src/lib/guards'
import { getModelPolicy, isModelId, isNearPolicy, type ModelPolicy, type PhalaModelPolicy } from '../src/lib/policy'

const MAX_CHAT_BYTES = 64 * 1024
const MAX_NRAS_BYTES = 256 * 1024
const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_BYTES = /^[0-9a-f]+$/i
const MAX_CIPHERTEXT_HEX_CHARS = 16_384
const CHAT_ID = /^[a-zA-Z0-9_-]{8,128}$/
const RECEIPT_ID = /^rcpt-[0-9a-f]{24}$/
const SESSION_ID = /^as_[0-9a-f]{64}$/
const EXACT_NEAR_CHAT_KEYS = new Set(['model', 'messages', 'max_tokens', 'stream'])
const EXACT_PHALA_CHAT_KEYS = new Set(['model', 'messages', 'max_tokens', 'stream', 'provider'])
const EXACT_PROVIDER_KEYS = new Set(['aci_verified'])
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

function upstreamUrl(policy: ModelPolicy, path: string, query = ''): string {
  return `https://${policy.endpointLabel}${path}${query}`
}

function policyFromRequest(request: Request): ModelPolicy | Response {
  const modelId = new URL(request.url).searchParams.get('model') ?? ''
  if (!isModelId(modelId)) return jsonResponse({ error: 'Model policy is not approved', code: 'unapproved_model' }, 400)
  return getModelPolicy(modelId)
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))
}

async function accessAllowed(request: Request, env: Env): Promise<boolean> {
  const expected = env.DEMO_ACCESS_TOKEN
  const supplied = request.headers.get('x-demo-access-token') ?? ''
  if (!expected || expected.length < 20 || supplied.length < 20 || supplied.length > 256) return false
  const [expectedHash, suppliedHash] = await Promise.all([sha256(expected), sha256(supplied)])
  let difference = 0
  for (let index = 0; index < expectedHash.length; index += 1) difference |= expectedHash[index]! ^ suppliedHash[index]!
  return difference === 0
}

async function requireAccess(request: Request, env: Env): Promise<Response | null> {
  if (!env.DEMO_ACCESS_TOKEN || env.DEMO_ACCESS_TOKEN.length < 20) {
    return jsonResponse({ error: 'Demo access gate is not configured', code: 'missing_access_gate' }, 503)
  }
  return await accessAllowed(request, env) ? null : jsonResponse({ error: 'Access token rejected', code: 'access_denied' }, 401)
}

async function boundedBody(request: Request, limit: number): Promise<ArrayBuffer> {
  const contentLength = request.headers.get('content-length')
  if (contentLength !== null) {
    const declared = Number(contentLength)
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > limit) throw new RangeError('request_too_large')
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

function requireApiKey(env: Env, policy: ModelPolicy): string | Response {
  const key = isNearPolicy(policy) ? env.NEAR_AI_API_KEY : env.PHALA_API_KEY
  if (!key) {
    return jsonResponse({ error: `${policy.providerLabel} API key is not configured`, code: 'missing_api_key' }, 503)
  }
  return key
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key))
}

function validCiphertext(value: unknown, minimumBytes: number): value is string {
  return typeof value === 'string'
    && value.length >= minimumBytes * 2
    && value.length <= MAX_CIPHERTEXT_HEX_CHARS
    && value.length % 2 === 0
    && HEX_BYTES.test(value)
}

function validNearEncryptedPrompt(value: unknown, policy: ModelPolicy): boolean {
  if (!isRecord(value)) return false
  if (!hasOnlyKeys(value, EXACT_NEAR_CHAT_KEYS)) return false
  if (value.model !== policy.model || value.stream !== false || value.max_tokens !== 256) return false
  if (!Array.isArray(value.messages) || value.messages.length !== 1) return false
  const message: unknown = value.messages[0]
  if (!isRecord(message)) return false
  return hasOnlyKeys(message, EXACT_MESSAGE_KEYS) && message.role === 'user' && validCiphertext(message.content, 73)
}

function validPhalaEncryptedPrompt(value: unknown, policy: PhalaModelPolicy): boolean {
  if (!isRecord(value)) return false
  if (!hasOnlyKeys(value, EXACT_PHALA_CHAT_KEYS)) return false
  if (value.model !== policy.model || value.stream !== false || value.max_tokens !== 512) return false
  if (!isRecord(value.provider)) return false
  if (!hasOnlyKeys(value.provider, EXACT_PROVIDER_KEYS) || value.provider.aci_verified !== true) return false
  if (!Array.isArray(value.messages) || value.messages.length !== 1) return false
  const message: unknown = value.messages[0]
  if (!isRecord(message)) return false
  return hasOnlyKeys(message, EXACT_MESSAGE_KEYS) && message.role === 'user' && validCiphertext(message.content, 60)
}

async function proxyAttestation(request: Request, upstreamFetch: FetchLike): Promise<Response> {
  if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405)
  const policy = policyFromRequest(request)
  if (policy instanceof Response) return policy
  const nonce = new URL(request.url).searchParams.get('nonce') ?? ''
  if (!HEX_32.test(nonce)) return jsonResponse({ error: 'nonce must be 32 bytes of hex' }, 400)
  const path = isNearPolicy(policy) ? '/v1/attestation/report' : '/v1/aci/attestation'
  const query = isNearPolicy(policy) ? `?signing_algo=ed25519&nonce=${nonce}` : `?nonce=${nonce}`
  const upstream = await upstreamFetch(upstreamUrl(policy, path, query), {
    headers: { accept: 'application/json' },
    redirect: 'manual',
  })
  if (!upstream.ok) return jsonResponse({ error: 'Attestation provider unavailable', code: 'upstream_attestation_error' }, 502)
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

async function proxyChat(request: Request, env: Env, upstreamFetch: FetchLike): Promise<Response> {
  if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405)
  const accessFailure = await requireAccess(request, env)
  if (accessFailure) return accessFailure
  const policy = policyFromRequest(request)
  if (policy instanceof Response) return policy
  const apiKey = requireApiKey(env, policy)
  if (apiKey instanceof Response) return apiKey
  const clientKey = request.headers.get('x-client-pub-key') ?? ''
  const modelKey = request.headers.get('x-model-pub-key') ?? ''
  if (!HEX_32.test(clientKey) || !HEX_32.test(modelKey)) return jsonResponse({ error: 'Invalid encryption key headers' }, 400)
  if (isNearPolicy(policy)) {
    if (request.headers.get('x-signing-algo') !== 'ed25519' || request.headers.get('x-encryption-version') !== '2') {
      return jsonResponse({ error: 'Only NEAR Ed25519 E2EE v2 is accepted' }, 400)
    }
  } else {
    const timestamp = Number(request.headers.get('x-e2ee-timestamp'))
    if (request.headers.get('x-e2ee-version') !== '2'
      || !HEX_32.test(request.headers.get('x-e2ee-nonce') ?? '')
      || !Number.isSafeInteger(timestamp)
      || Math.abs(Math.floor(Date.now() / 1000) - timestamp) > 300) {
      return jsonResponse({ error: 'Only fresh Phala ACI E2EE v2 requests are accepted' }, 400)
    }
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
  const valid = isNearPolicy(policy) ? validNearEncryptedPrompt(parsed, policy) : validPhalaEncryptedPrompt(parsed, policy)
  if (!valid) return jsonResponse({ error: 'Only the pinned encrypted prompt shape is accepted' }, 400)
  const headers = new Headers({
    accept: 'application/json',
    'accept-encoding': 'identity',
    authorization: `Bearer ${apiKey}`,
    'content-type': 'application/json',
    'x-client-pub-key': clientKey,
    'x-model-pub-key': modelKey,
  })
  if (isNearPolicy(policy)) {
    headers.set('x-encryption-version', '2')
    headers.set('x-no-aliasing', 'true')
    headers.set('x-signing-algo', 'ed25519')
  } else {
    headers.set('x-e2ee-version', '2')
    headers.set('x-e2ee-nonce', request.headers.get('x-e2ee-nonce')!)
    headers.set('x-e2ee-timestamp', request.headers.get('x-e2ee-timestamp')!)
  }
  const upstream = await upstreamFetch(upstreamUrl(policy, '/v1/chat/completions'), {
    method: 'POST',
    headers,
    body,
    redirect: 'manual',
  })
  if (!upstream.ok) return jsonResponse({ error: `Confidential model returned HTTP ${upstream.status}`, code: 'upstream_chat_error' }, upstream.status)
  const responseHeaders = new Headers({
    'content-type': upstream.headers.get('content-type') ?? 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  const requestId = upstream.headers.get('x-request-id')
  if (requestId) responseHeaders.set('x-request-id', requestId)
  if (!isNearPolicy(policy)) {
    const receiptId = upstream.headers.get('x-receipt-id') ?? ''
    if (upstream.headers.get('x-e2ee-applied') !== 'true' || upstream.headers.get('x-e2ee-version') !== '2' || !RECEIPT_ID.test(receiptId)) {
      return jsonResponse({ error: 'Phala response omitted required E2EE or receipt evidence', code: 'upstream_evidence_error' }, 502)
    }
    responseHeaders.set('x-e2ee-applied', 'true')
    responseHeaders.set('x-e2ee-version', '2')
    responseHeaders.set('x-receipt-id', receiptId)
  }
  return new Response(upstream.body, { status: upstream.status, headers: responseHeaders })
}

async function proxySignature(request: Request, env: Env, upstreamFetch: FetchLike, chatId: string): Promise<Response> {
  if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405)
  const accessFailure = await requireAccess(request, env)
  if (accessFailure) return accessFailure
  const policy = policyFromRequest(request)
  if (policy instanceof Response) return policy
  if (!isNearPolicy(policy)) return jsonResponse({ error: 'NEAR signature route is unavailable for this provider' }, 400)
  const apiKey = requireApiKey(env, policy)
  if (apiKey instanceof Response) return apiKey
  if (!CHAT_ID.test(chatId)) return jsonResponse({ error: 'Invalid chat id' }, 400)
  const upstream = await upstreamFetch(upstreamUrl(policy, `/v1/signature/${chatId}`, '?signing_algo=ed25519'), {
    headers: { accept: 'application/json', authorization: `Bearer ${apiKey}` },
    redirect: 'manual',
  })
  if (upstream.status === 404) return jsonResponse({ error: 'Signature not found' }, 404)
  if (!upstream.ok) return jsonResponse({ error: 'Signature provider unavailable', code: 'upstream_signature_error' }, 502)
  return new Response(upstream.body, { status: upstream.status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } })
}

async function proxyPhalaEvidence(request: Request, env: Env, upstreamFetch: FetchLike, kind: 'receipts' | 'sessions', id: string): Promise<Response> {
  if (request.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405)
  const accessFailure = await requireAccess(request, env)
  if (accessFailure) return accessFailure
  const policy = policyFromRequest(request)
  if (policy instanceof Response) return policy
  if (isNearPolicy(policy)) return jsonResponse({ error: 'Phala evidence route is unavailable for this provider' }, 400)
  const validId = kind === 'receipts' ? RECEIPT_ID.test(id) : SESSION_ID.test(id)
  if (!validId) return jsonResponse({ error: `Invalid Phala ${kind} id` }, 400)
  const apiKey = requireApiKey(env, policy)
  if (apiKey instanceof Response) return apiKey
  const upstream = await upstreamFetch(upstreamUrl(policy, `/v1/aci/${kind}/${id}`), {
    headers: { accept: 'application/json', authorization: `Bearer ${apiKey}` },
    redirect: 'manual',
  })
  if (upstream.status === 404) return jsonResponse({ error: `Phala ${kind} record not found` }, 404)
  if (!upstream.ok) return jsonResponse({ error: `Phala ${kind} provider unavailable`, code: 'upstream_evidence_error' }, 502)
  return new Response(upstream.body, { status: upstream.status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } })
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
    if (payload.arch !== 'HOPPER' || !HEX_32.test(String(payload.nonce ?? '')) || !Array.isArray(payload.evidence_list) || payload.evidence_list.length !== 8) {
      return jsonResponse({ error: 'Malformed GPU evidence' }, 400)
    }
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
  return new Response(upstream.body, { status: upstream.status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } })
}

export async function handleApiRequest(request: Request, env: Env, upstreamFetch: FetchLike = fetch): Promise<Response> {
  const url = new URL(request.url)
  if (url.pathname === '/api/access') {
    if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405)
    const accessFailure = await requireAccess(request, env)
    return accessFailure ?? new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } })
  }
  if (url.pathname === '/api/attestation') return proxyAttestation(request, upstreamFetch)
  if (url.pathname === '/api/chat') return proxyChat(request, env, upstreamFetch)
  if (url.pathname === '/api/nras') return proxyNras(request, upstreamFetch)
  if (url.pathname.startsWith('/api/signature/')) return proxySignature(request, env, upstreamFetch, url.pathname.slice('/api/signature/'.length))
  if (url.pathname.startsWith('/api/phala/receipts/')) return proxyPhalaEvidence(request, env, upstreamFetch, 'receipts', url.pathname.slice('/api/phala/receipts/'.length))
  if (url.pathname.startsWith('/api/phala/sessions/')) return proxyPhalaEvidence(request, env, upstreamFetch, 'sessions', url.pathname.slice('/api/phala/sessions/'.length))
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
