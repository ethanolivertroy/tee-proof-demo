/**
 * E2EE v2 channel to a *verified* workload (spec/e2ee-v2.md). `openE2eeChannel`
 * refuses unless the keyset comes from a report that passed
 * {@link verifyReportBinding}: you cannot encrypt to a key that is not in a
 * quote-bound keyset. `seal` encrypts the request's message contents to the
 * attested X25519 key and returns the five `X-E2EE-*` request headers
 * (e2ee-v2 §3.1); `open` decrypts the buffered response. Only the non-streamed
 * chat-completion shape this demo sends is supported; other request shapes
 * fail closed. Channel crypto is Web Crypto (X25519, HKDF-SHA256, AES-256-GCM,
 * e2ee-v2 §4).
 */

import { bytesToHex } from '../encoding'
import { fromHex } from './crypto'
import { requestAad, responseAad } from './e2ee'
import type { ReportVerification } from './types'

const ALGO = 'x25519-aes-256-gcm-hkdf-sha256'
const subtle = globalThis.crypto.subtle
const enc = new TextEncoder()
const dec = new TextDecoder()
const HKDF_INFO = enc.encode('aci.e2ee.v2.x25519')

type Json = Record<string, unknown>

/** An encrypted channel bound to one verified workload. */
export interface E2eeChannel {
  /** Encrypt a request's message contents; returns the body and `X-E2EE-*` headers. */
  seal(request: Json): Promise<{ body: Json; headers: Record<string, string> }>
  /** Decrypt a buffered response produced for the most recent `seal`. */
  open(response: Json): Promise<Json>
}

/** The exact E2EE key already approved by the full gateway verifier. */
export interface ApprovedE2eeKey {
  keyId: string
  algorithm: string
  publicKey: string
}

/**
 * Open an E2EE channel to the workload whose keyset `verification` (from
 * {@link verifyReportBinding}) established, encrypting to `approvedKey`.
 */
export async function openE2eeChannel(verification: ReportVerification, approvedKey: ApprovedE2eeKey): Promise<E2eeChannel> {
  if (!verification.ok || !verification.keyset) {
    throw new Error('openE2eeChannel: report is not verified; call verifyReportBinding and check .ok')
  }
  const keys = Array.isArray(verification.keyset.e2ee_public_keys) ? verification.keyset.e2ee_public_keys : []
  const service = keys.find((key) => key?.key_id === approvedKey.keyId)
  if (
    approvedKey.algorithm !== ALGO ||
    !service ||
    service.algo !== approvedKey.algorithm ||
    service.public_key !== approvedKey.publicKey
  ) {
    throw new Error('openE2eeChannel: approved E2EE key is missing or changed')
  }
  const serviceRaw = fromHex(service.public_key)
  if (serviceRaw.length !== 32) throw new Error('openE2eeChannel: X25519 service key must be 32 bytes')

  // Static client key: responses are encrypted to it, and we decrypt with its private half.
  const client = (await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair
  const clientPubHex = bytesToHex(new Uint8Array(await subtle.exportKey('raw', client.publicKey)))

  let sent: { model: string; nonce: string; ts: number } | undefined
  let state: 'idle' | 'sealing' | 'awaiting' | 'opening' = 'idle'

  return {
    async seal(request) {
      if (state !== 'idle') throw new Error('seal: prior response is still pending')
      state = 'sealing'
      try {
        const model = request.model
        if (typeof model !== 'string') throw new Error('seal: request.model must be a string')
        if (!Array.isArray(request.messages)) throw new Error('seal: request.messages must be an array')
        const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
        const ts = Math.floor(Date.now() / 1000)
        const encField = (text: string, field: string) =>
          sealField(serviceRaw, enc.encode(text), requestAad({ algo: ALGO, model, field, nonce, ts }))

        // Whole-content encryption (e2ee-v2 §5): every message's content is sealed.
        const messages = await Promise.all(
          (request.messages as Json[]).map(async (m, i) => {
            if (m?.content == null) return m
            const text = typeof m.content === 'string' ? m.content : JSON.stringify(m.content)
            return { ...m, content: await encField(text, `messages.${i}.content`) }
          }),
        )
        sent = { model, nonce, ts }
        state = 'awaiting'
        return {
          body: { ...request, messages },
          headers: {
            'X-E2EE-Version': '2',
            'X-Client-Pub-Key': clientPubHex,
            'X-Model-Pub-Key': service.public_key,
            'X-E2EE-Nonce': nonce,
            'X-E2EE-Timestamp': String(ts),
          },
        }
      } catch (error) {
        sent = undefined
        state = 'idle'
        throw error
      }
    },

    async open(response) {
      if (state !== 'awaiting') throw new Error('open: call seal first or wait for the pending response')
      state = 'opening'
      try {
        const decField = responseDecryptor(client.privateKey, sent, textFrom(response.id))
        const body: Json = { ...response }
        if (Array.isArray(response.choices)) {
          body.choices = await Promise.all(
            (response.choices as Json[]).map(async (c, pos) => {
              const i = indexOf(c, pos)
              const out: Json = { ...c }
              if (out.message && typeof out.message === 'object') {
                const m: Json = { ...(out.message as Json) }
                // e2ee-v2 §5 also encrypts `audio.data`; this text-only demo
                // never requests audio, so its presence in any form fails closed.
                if (Object.hasOwn(m, 'audio')) throw new Error('open: unsupported response field choices.message.audio')
                for (const key of ['content', 'reasoning', 'reasoning_content']) {
                  await openStr(m, key, `choices.${i}.message.${key}`, decField)
                }
                out.message = m
              }
              return out
            }),
          )
        }
        return body
      } finally {
        sent = undefined
        state = 'idle'
      }
    },
  }
}

/** A field decryptor bound to the request context (e2ee-v2 §6) and the response `id`. */
function responseDecryptor(
  clientPriv: CryptoKey,
  sent: { model: string; nonce: string; ts: number } | undefined,
  id: string,
): (blobHex: string, field: string) => Promise<string> {
  if (!sent) throw new Error('open: call seal first')
  const { model, nonce, ts } = sent
  return async (blobHex, field) =>
    dec.decode(await openField(clientPriv, blobHex, responseAad({ algo: ALGO, model, id, field, nonce, ts })))
}

/** `choices` index is the entry's `index` member, else its array position (e2ee-v2 §5). */
function indexOf(entry: Json, position: number): number {
  return typeof entry.index === 'number' ? entry.index : position
}

function textFrom(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

/**
 * Decrypt string member `key` of `obj` at `field`, in place. A `null` member
 * carries no content and stays; any other non-string value could carry
 * plaintext the service was required to encrypt (e2ee-v2 §5), so it fails
 * closed. A string that is not well-formed ciphertext fails in `openField`.
 */
async function openStr(
  obj: Json,
  key: string,
  field: string,
  decField: (blobHex: string, field: string) => Promise<string>,
): Promise<void> {
  const value = obj[key]
  if (value === undefined || value === null) return
  if (typeof value !== 'string') throw new Error(`open: unsupported unencrypted response field ${field}`)
  obj[key] = await decField(value, field)
}

// `Uint8Array` to `BufferSource` (Web Crypto typings friction).
const bs = (u: Uint8Array): BufferSource => u as BufferSource

/** Derive the AES-256-GCM key from a raw X25519 shared secret (e2ee-v2 §4). */
async function aesKey(shared: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  const hk = await subtle.importKey('raw', bs(shared), 'HKDF', false, ['deriveKey'])
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: bs(new Uint8Array(0)), info: bs(HKDF_INFO) },
    hk,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  )
}

/** Encrypt one field to `serviceRaw` with a fresh ephemeral key, as wire hex (e2ee-v2 §4). */
async function sealField(serviceRaw: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<string> {
  const eph = (await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair
  const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey))
  const service = await subtle.importKey('raw', bs(serviceRaw), { name: 'X25519' }, false, [])
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: service }, eph.privateKey, 256))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: bs(iv), additionalData: bs(aad) }, await aesKey(shared, 'encrypt'), bs(plaintext)))
  const blob = new Uint8Array(ephPub.length + iv.length + ct.length)
  blob.set(ephPub)
  blob.set(iv, ephPub.length)
  blob.set(ct, ephPub.length + iv.length)
  return bytesToHex(blob)
}

/** Decrypt one field addressed to the client static key. */
async function openField(clientPriv: CryptoKey, blobHex: string, aad: Uint8Array): Promise<Uint8Array> {
  const blob = fromHex(blobHex)
  if (blob.length < 32 + 12 + 16) throw new Error('open: encrypted field is too short')
  const ephPub = await subtle.importKey('raw', bs(blob.slice(0, 32)), { name: 'X25519' }, false, [])
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: ephPub }, clientPriv, 256))
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: bs(blob.slice(32, 44)), additionalData: bs(aad) }, await aesKey(shared, 'decrypt'), bs(blob.slice(44)))
  return new Uint8Array(pt)
}
