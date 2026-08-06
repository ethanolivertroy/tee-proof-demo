/**
 * Cryptographic primitives shared by browser and Node runtimes. SHA-256 and
 * Ed25519 use Web Crypto; ACI secp256k1 verification uses the audited
 * `@noble/curves` implementation because that curve is absent from Web Crypto.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { AciFormatError, UnsupportedAlgorithmError } from './errors.js';

const subtle = globalThis.crypto.subtle;

/** Lowercase-hex encode bytes. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Decode strict hex (optionally `0x`-prefixed) to bytes. */
export function fromHex(hex: string): Uint8Array {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) {
    throw new AciFormatError(`hex string has odd length: ${h.length} chars`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = h.slice(i * 2, i * 2 + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
      throw new AciFormatError(`invalid hex at offset ${i * 2}: "${pair}"`);
    }
    out[i] = Number.parseInt(pair, 16);
  }
  return out;
}

/** SHA-256 of the given bytes. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', bytes as BufferSource));
}

/** Lowercase-hex SHA-256 of the given bytes. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(await sha256(bytes));
}

/**
 * `sha256:<lowercase-hex>` digest string of the given bytes — the ACI digest
 * form (§3) used for `workload_id`, keyset digests, and body hashes.
 */
export async function sha256Prefixed(bytes: Uint8Array): Promise<string> {
  return 'sha256:' + (await sha256Hex(bytes));
}

/**
 * Verify an Ed25519 signature (RFC 8032, §4.3/§8.5) over `message`.
 * `publicKeyRaw` is the 32-byte raw key; `signature` the 64-byte value.
 * Returns false on a bad signature or malformed key — never throws for those.
 */
export async function verifyEd25519(
  publicKeyRaw: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  let key: CryptoKey;
  try {
    key = await subtle.importKey('raw', publicKeyRaw as BufferSource, { name: 'Ed25519' }, false, [
      'verify',
    ]);
  } catch {
    // A key that will not import cannot verify anything.
    return false;
  }
  try {
    return await subtle.verify({ name: 'Ed25519' }, key, signature as BufferSource, message as BufferSource);
  } catch {
    return false;
  }
}

/** Normalize the 64-byte x‖y and 65-byte uncompressed secp256k1 encodings. */
function normalizeSecp256k1PublicKey(publicKeyRaw: Uint8Array): Uint8Array {
  if (publicKeyRaw.length === 64) return Uint8Array.of(0x04, ...publicKeyRaw);
  if (publicKeyRaw.length === 65 && publicKeyRaw[0] === 0x04) return publicKeyRaw;
  throw new AciFormatError(`secp256k1 public key must be 64 or 65 bytes, got ${publicKeyRaw.length}`);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i]! ^ right[i]!;
  return diff === 0;
}

/**
 * Verify an ACI secp256k1 signature. Keyset endorsements use compact r‖s over
 * SHA-256(message). Receipts use r‖s‖v and must recover the listed public key.
 */
async function verifySecp256k1(
  publicKeyRaw: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  let publicKey: Uint8Array;
  try {
    publicKey = normalizeSecp256k1PublicKey(publicKeyRaw);
  } catch {
    return false;
  }

  if (signature.length === 64) {
    return secp256k1.verify(signature, message, publicKey);
  }
  if (signature.length !== 65) return false;

  let recovery = signature[64]!;
  if (recovery >= 27 && recovery <= 30) recovery -= 27;
  if (recovery > 3) return false;
  try {
    const compact = signature.slice(0, 64);
    const parsed = secp256k1.Signature.fromBytes(compact, 'compact');
    if (parsed.hasHighS()) return false;
    const digest = await sha256(message);
    const recovered = parsed
      .addRecoveryBit(recovery)
      .recoverPublicKey(digest)
      .toBytes(false);
    return equalBytes(recovered, publicKey);
  } catch {
    return false;
  }
}

/** Verify a signature under the exact algorithm declared by the attested key. */
export async function verifySignature(
  algo: string,
  publicKeyRaw: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
  context: string,
): Promise<boolean> {
  if (algo === 'ed25519') return verifyEd25519(publicKeyRaw, signature, message);
  if (algo === 'ecdsa-secp256k1') return verifySecp256k1(publicKeyRaw, signature, message);
  throw new UnsupportedAlgorithmError(algo, context);
}
