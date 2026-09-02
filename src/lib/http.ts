import { assert } from './guards'

const MAX_RESPONSE_BYTES = 2_000_000

export function accessHeaders(accessToken: string): Record<string, string> {
  return { 'x-demo-access-token': accessToken }
}

/**
 * Reads a Worker response body while counting bytes, and cancels the stream
 * the moment it crosses the cap so an oversized upstream body is never fully
 * buffered in the tab.
 */
export async function readBoundedText(response: Response, limit = MAX_RESPONSE_BYTES): Promise<string> {
  if (!response.body) return ''
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > limit) {
        await reader.cancel().catch(() => undefined)
        throw new Error('Provider response exceeded the client limit')
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(bytes)
}

export interface BoundedResponse {
  response: Response
  text: string
}

export async function fetchBounded(path: string, init?: RequestInit): Promise<BoundedResponse> {
  const response = await fetch(path, { cache: 'no-store', ...init })
  const text = await readBoundedText(response)
  return { response, text }
}

export async function fetchJson(path: string, init?: RequestInit): Promise<unknown> {
  const { response, text } = await fetchBounded(path, init)
  assert(response.ok, `Request failed (${response.status}): ${text.slice(0, 180)}`)
  return JSON.parse(text) as unknown
}
