/**
 * Decoding and signature primitives for the ACI artifacts. ACI's only
 * signature algorithm is Ed25519 and its only hash is SHA-256 (Appendix B);
 * both come from the audited `@noble` implementations the rest of src/lib
 * uses (see ../crypto), not from Web Crypto, so the same code runs in the
 * worker, in tests, and in Node.
 */

import { verifyEd25519Bytes } from '../crypto'
import { AciFormatError } from './errors'

/**
 * Decode strict hex (optionally `0x`-prefixed) to bytes. This deliberately is
 * not `encoding.hexToBytes`: malformed input must surface as
 * {@link AciFormatError} so `verifyReceipt` can convert it into a failed check
 * instead of a thrown error, and the empty string (an absent value) is accepted.
 */
export function fromHex(hex: string): Uint8Array {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex
  if (h.length % 2 !== 0) {
    throw new AciFormatError(`hex string has odd length: ${h.length} chars`)
  }
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) {
    const pair = h.slice(i * 2, i * 2 + 2)
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
      throw new AciFormatError(`invalid hex at offset ${i * 2}: "${pair}"`)
    }
    out[i] = Number.parseInt(pair, 16)
  }
  return out
}

/** Decode standard base64 (RFC 4648 §4) to the exact underlying bytes. */
export function fromBase64(b64: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) {
    throw new AciFormatError('invalid base64')
  }
  let bin: string
  try {
    bin = atob(b64)
  } catch {
    throw new AciFormatError('invalid base64')
  }
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/**
 * Verify an Ed25519 signature (RFC 8032) over `message`. `publicKeyRaw` is the
 * 32-byte raw key; `signature` the 64-byte value. Returns false on a bad
 * signature or malformed key, never throws for those.
 */
export function verifyEd25519(publicKeyRaw: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean {
  if (publicKeyRaw.length !== 32 || signature.length !== 64) return false
  return verifyEd25519Bytes(signature, message, publicKeyRaw)
}
