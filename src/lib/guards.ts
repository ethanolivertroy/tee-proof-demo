export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message)
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function asRecord(value: unknown, message: string): Record<string, unknown> {
  assert(isRecord(value), message)
  return value
}

/**
 * `asRecord` plus rejection of prototype-pollution key names, for JSON parsed
 * from an untrusted wire response.
 */
export function assertPlainObject(value: unknown, message: string): asserts value is Record<string, unknown> {
  assert(isRecord(value), message)
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    assert(!Object.prototype.hasOwnProperty.call(value, key), `Unsafe response key: ${key}`)
  }
}
