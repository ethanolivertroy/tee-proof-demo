// Fail-closed cap on any JSON body this client will buffer from the Worker.
const MAX_JSON_RESPONSE_CHARS = 2_000_000

export function accessHeaders(accessToken: string): Record<string, string> {
  return { 'x-demo-access-token': accessToken }
}

export async function fetchJson(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(path, init)
  const text = await response.text()
  if (text.length > MAX_JSON_RESPONSE_CHARS) throw new Error('Provider response exceeded the client limit')
  if (!response.ok) throw new Error(`Request failed (${response.status}): ${text.slice(0, 180)}`)
  return JSON.parse(text)
}
