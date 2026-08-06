import { describe, expect, it } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { capEvidenceExpiry, parseCompletionResponse, verifyCompletionSignature } from '../src/lib/api'
import { sha256Hex } from '../src/lib/crypto'
import { bytesToHex, textEncoder } from '../src/lib/encoding'
import { POLICY } from '../src/lib/policy'
import type { TrustEvidence } from '../src/lib/types'

function evidence(signingPublicKey: string): TrustEvidence {
  return {
    modelId: POLICY.id,
    provider: 'near-ai',
    protocol: 'near-e2ee-v2',
    verifiedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    nonce: 'a'.repeat(64),
    model: POLICY.model,
    endpointLabel: POLICY.endpointLabel,
    signingPublicKey,
    policyDigest: 'b'.repeat(64),
    composeHash: 'c'.repeat(64),
    osImageHash: 'd'.repeat(64),
    cpu: {} as TrustEvidence['cpu'],
    gpu: {} as TrustEvidence['gpu'],
    raw: {} as TrustEvidence['raw'],
  }
}

describe('fail-closed client protocol', () => {
  it('caps evidence at five minutes and rejects already expired evidence', () => {
    const now = Date.parse('2026-08-06T12:00:00Z')
    expect(capEvidenceExpiry('2026-08-06T13:00:00Z', now)).toBe('2026-08-06T12:05:00.000Z')
    expect(() => capEvidenceExpiry('2026-08-06T11:59:59Z', now)).toThrow(/expired/)
  })

  it('accepts the pinned response shape and rejects model or metadata substitutions', () => {
    const valid = { id: 'chat-123', model: POLICY.model, choices: [{ message: { content: 'aa' } }] }
    expect(parseCompletionResponse(valid).id).toBe('chat-123')
    expect(() => parseCompletionResponse({ ...valid, model: 'evil/model' })).toThrow(/model/)
    expect(() => parseCompletionResponse({ ...valid, prompt_text: 'leak' })).toThrow(/non-null/)
    expect(() => parseCompletionResponse({ ...valid, upstream_url: 'https://evil.test' })).toThrow(/Unexpected/)
  })

  it('authenticates the exact encrypted request and response bytes', () => {
    const seed = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
    const publicKey = bytesToHex(ed25519.getPublicKey(seed))
    const requestText = '{"ciphertext":"aa"}'
    const responseText = '{"ciphertext":"bb"}'
    const signedText = `${POLICY.model}:${sha256Hex(requestText)}:${sha256Hex(responseText)}`
    const signature = bytesToHex(ed25519.sign(textEncoder.encode(signedText), seed))
    const report = { text: signedText, signature, signing_address: publicKey, signing_algo: 'ed25519' }
    expect(verifyCompletionSignature(report, evidence(publicKey), requestText, responseText).signer).toBe(publicKey)
    expect(() => verifyCompletionSignature(report, evidence(publicKey), requestText, `${responseText} `)).toThrow(/exact request and response/)
  })
})
