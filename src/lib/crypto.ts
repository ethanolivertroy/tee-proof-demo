import { randomBytes } from '@noble/ciphers/utils.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, hexToBytes, textDecoder, textEncoder } from './encoding'

const HKDF_INFO = textEncoder.encode('ed25519_encryption')
const PUBLIC_KEY_LENGTH = 32
const NONCE_LENGTH = 24
const TAG_LENGTH = 16

export interface ClientKeys {
  ed25519PublicKey: Uint8Array
  x25519SecretKey: Uint8Array
}

export function generateClientKeys(): ClientKeys {
  const seed = ed25519.utils.randomSecretKey()
  return {
    ed25519PublicKey: ed25519.getPublicKey(seed),
    x25519SecretKey: ed25519.utils.toMontgomerySecret(seed),
  }
}

export function seal(
  plaintext: Uint8Array,
  recipientX25519PublicKey: Uint8Array,
  ephemeralSecret = x25519.utils.randomSecretKey(),
  nonce = randomBytes(NONCE_LENGTH),
): Uint8Array {
  if (recipientX25519PublicKey.length !== PUBLIC_KEY_LENGTH) throw new Error('Recipient key must be 32 bytes')
  if (ephemeralSecret.length !== PUBLIC_KEY_LENGTH) throw new Error('Ephemeral key must be 32 bytes')
  if (nonce.length !== NONCE_LENGTH) throw new Error('Nonce must be 24 bytes')

  const ephemeralPublic = x25519.getPublicKey(ephemeralSecret)
  const sharedSecret = x25519.getSharedSecret(ephemeralSecret, recipientX25519PublicKey)
  const symmetricKey = hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32)
  const ciphertext = xchacha20poly1305(symmetricKey, nonce).encrypt(plaintext)
  return concatBytes(ephemeralPublic, nonce, ciphertext)
}

export function open(sealed: Uint8Array, recipientX25519SecretKey: Uint8Array): Uint8Array {
  if (sealed.length < PUBLIC_KEY_LENGTH + NONCE_LENGTH + TAG_LENGTH) throw new Error('Encrypted field is too short')
  if (recipientX25519SecretKey.length !== PUBLIC_KEY_LENGTH) throw new Error('Recipient secret must be 32 bytes')

  const ephemeralPublic = sealed.slice(0, PUBLIC_KEY_LENGTH)
  const nonce = sealed.slice(PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH + NONCE_LENGTH)
  const ciphertext = sealed.slice(PUBLIC_KEY_LENGTH + NONCE_LENGTH)
  const sharedSecret = x25519.getSharedSecret(recipientX25519SecretKey, ephemeralPublic)
  const symmetricKey = hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32)
  return xchacha20poly1305(symmetricKey, nonce).decrypt(ciphertext)
}

export function encryptForModel(plaintext: string, modelEd25519PublicKeyHex: string): string {
  const modelEd25519PublicKey = hexToBytes(modelEd25519PublicKeyHex)
  if (modelEd25519PublicKey.length !== PUBLIC_KEY_LENGTH) throw new Error('Model Ed25519 key must be 32 bytes')
  const modelX25519PublicKey = ed25519.utils.toMontgomery(modelEd25519PublicKey)
  return bytesToHex(seal(textEncoder.encode(plaintext), modelX25519PublicKey))
}

export function decryptFromModel(encryptedHex: string, clientX25519SecretKey: Uint8Array): string {
  return textDecoder.decode(open(hexToBytes(encryptedHex), clientX25519SecretKey))
}

export function verifyEd25519Signature(signatureHex: string, message: string, publicKeyHex: string): boolean {
  return ed25519.verify(hexToBytes(signatureHex), textEncoder.encode(message), hexToBytes(publicKeyHex))
}

export function sha256Hex(value: string): string {
  return bytesToHex(sha256(textEncoder.encode(value)))
}
