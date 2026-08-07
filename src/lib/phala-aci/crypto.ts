/**
 * ACI signature verification. All primitives are the same audited `@noble`
 * implementations the rest of src/lib uses: SHA-256 from @noble/hashes,
 * strict Ed25519 from ../crypto, secp256k1 from @noble/curves (that curve is
 * absent from Web Crypto).
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { normalizeSecp256k1RecoveryId, verifyEd25519Bytes } from '../crypto'
import { equalBytes } from '../encoding'
import { AciFormatError, UnsupportedAlgorithmError } from './errors'

/**
 * Decode strict hex (optionally `0x`-prefixed) to bytes. This deliberately is
 * not `encoding.hexToBytes`: malformed input must surface as
 * {@link AciFormatError} so `verifyReceipt` and `verifyReportBinding` can
 * convert it into a failed check instead of a thrown error, and the empty
 * string (an absent value) is accepted.
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

/** Normalize the 64-byte x||y and 65-byte uncompressed secp256k1 encodings. */
function normalizeSecp256k1PublicKey(publicKeyRaw: Uint8Array): Uint8Array {
  if (publicKeyRaw.length === 64) return Uint8Array.of(0x04, ...publicKeyRaw)
  if (publicKeyRaw.length === 65 && publicKeyRaw[0] === 0x04) return publicKeyRaw
  throw new AciFormatError(`secp256k1 public key must be 64 or 65 bytes, got ${publicKeyRaw.length}`)
}

/**
 * Verify an ACI secp256k1 signature. Keyset endorsements use compact r||s over
 * SHA-256(message). Receipts use r||s||v and must recover the listed public key.
 */
function verifySecp256k1(publicKeyRaw: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean {
  let publicKey: Uint8Array
  try {
    publicKey = normalizeSecp256k1PublicKey(publicKeyRaw)
  } catch {
    return false
  }

  if (signature.length === 64) {
    return secp256k1.verify(signature, message, publicKey)
  }
  if (signature.length !== 65) return false

  const recovery = normalizeSecp256k1RecoveryId(signature[64]!)
  if (recovery === null) return false
  try {
    const parsed = secp256k1.Signature.fromBytes(signature.slice(0, 64), 'compact')
    if (parsed.hasHighS()) return false
    const recovered = parsed
      .addRecoveryBit(recovery)
      .recoverPublicKey(sha256(message))
      .toBytes(false)
    return equalBytes(recovered, publicKey)
  } catch {
    return false
  }
}

/** Verify a signature under the exact algorithm declared by the attested key. */
export function verifySignature(
  algo: string,
  publicKeyRaw: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
  context: string,
): boolean {
  if (algo === 'ed25519') return verifyEd25519Bytes(signature, message, publicKeyRaw)
  if (algo === 'ecdsa-secp256k1') return verifySecp256k1(publicKeyRaw, signature, message)
  throw new UnsupportedAlgorithmError(algo, context)
}
