import { describe, expect, it } from 'vitest'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, hexToBytes, textDecoder, textEncoder } from '../src/lib/encoding'
import { open, seal, sha256Hex, verifyEd25519Signature } from '../src/lib/crypto'

const ED25519_PUBLIC = '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8'
const X25519_PUBLIC = '4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01'
const EXPECTED_WIRE = '132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472000102030405060708090a0b0c0d0e0f10111213141516173418f5b2ea21454e495da2f5ed36d4dccf6a23c2471a29092b6137e8805b820451014121b74c'

describe('NEAR E2EE v2 crypto', () => {
  it('matches an independent PyNaCl and cryptography known-answer vector', () => {
    const edPublic = hexToBytes(ED25519_PUBLIC)
    expect(bytesToHex(ed25519.utils.toMontgomery(edPublic))).toBe(X25519_PUBLIC)
    const wire = seal(
      textEncoder.encode('known NEAR E2EE vector'),
      hexToBytes(X25519_PUBLIC),
      new Uint8Array(32).fill(0x42),
      Uint8Array.from({ length: 24 }, (_, index) => index),
    )
    expect(bytesToHex(wire)).toBe(EXPECTED_WIRE)
  })

  it('round-trips a response encrypted to an Ed25519-derived client key', () => {
    const seed = Uint8Array.from({ length: 32 }, (_, index) => 31 - index)
    const edPublic = ed25519.getPublicKey(seed)
    const xSecret = ed25519.utils.toMontgomerySecret(seed)
    const xPublic = ed25519.utils.toMontgomery(edPublic)
    const wire = seal(textEncoder.encode('attested response'), xPublic)
    expect(textDecoder.decode(open(wire, xSecret))).toBe('attested response')
    expect(bytesToHex(x25519.getPublicKey(xSecret))).toBe(bytesToHex(xPublic))
  })

  it('verifies Ed25519 signatures over exact SHA-256 inputs', () => {
    const seed = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
    const publicKey = ed25519.getPublicKey(seed)
    const message = 'model:request-hash:response-hash'
    const signature = ed25519.sign(textEncoder.encode(message), seed)
    expect(verifyEd25519Signature(bytesToHex(signature), message, bytesToHex(publicKey))).toBe(true)
    expect(verifyEd25519Signature(bytesToHex(signature), `${message}!`, bytesToHex(publicKey))).toBe(false)
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
})
