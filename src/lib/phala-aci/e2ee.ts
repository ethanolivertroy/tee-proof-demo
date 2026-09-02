/**
 * E2EE v2 associated-data (AAD) builders (spec/e2ee-v2.md §6). The AAD binds
 * each ciphertext to its field path and request context; it is the JCS of a
 * purpose-tagged object, so no component needs bespoke escaping. The exact
 * bytes are pinned in spec/e2ee-v2-test-vectors.md.
 */

import { jcsBytes } from './jcs'

/** Inputs shared by request and response AAD (e2ee-v2 §6). */
export interface AadCommon {
  /** `algo` of the selected service E2EE key. */
  algo: string
  /** The request's top-level `model`, byte-exact. */
  model: string
  /** The encrypted location's field path, e.g. `messages.0.content` (e2ee-v2 §5). */
  field: string
  /** The request's `X-E2EE-Nonce` (string). */
  nonce: string
  /** The request's `X-E2EE-Timestamp` (Unix seconds, integer). */
  ts: number
}

/** Request AAD (e2ee-v2 §6), tag `aci.e2ee.request.v2`, as the UTF-8 JCS bytes passed to AES-GCM. */
export function requestAad(params: AadCommon): Uint8Array {
  return jcsBytes({
    purpose: 'aci.e2ee.request.v2',
    algo: params.algo,
    model: params.model,
    field: params.field,
    nonce: params.nonce,
    ts: params.ts,
  })
}

/** Response AAD (e2ee-v2 §6), tag `aci.e2ee.response.v2`. Adds the response `id` (`""` when none). */
export function responseAad(params: AadCommon & { id: string }): Uint8Array {
  return jcsBytes({
    purpose: 'aci.e2ee.response.v2',
    algo: params.algo,
    model: params.model,
    id: params.id,
    field: params.field,
    nonce: params.nonce,
    ts: params.ts,
  })
}
