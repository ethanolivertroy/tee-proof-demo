import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, it } from 'vitest'
import { capEvidenceExpiry, parseCompletionResponse, verifyCompletionSignature } from '../src/lib/api'
import { sha256Hex } from '../src/lib/crypto'
import { bytesToHex, textEncoder } from '../src/lib/encoding'
import { getModelPolicy, isNearPolicy } from '../src/lib/policy'
import type { NearTrustEvidence } from '../src/lib/types'

const policy = getModelPolicy('deepseek-v4-flash')
if (!isNearPolicy(policy)) throw new Error('Expected NEAR policy')

function evidence(signingPublicKey: string): NearTrustEvidence {
  return {
    modelId: policy.id,
    provider: 'near-ai',
    protocol: 'near-e2ee-v2',
    verifiedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    nonce: 'a'.repeat(64),
    model: policy.model,
    endpointLabel: policy.endpointLabel,
    signingPublicKey,
    policyDigest: 'b'.repeat(64),
    composeHash: 'c'.repeat(64),
    osImageHash: 'd'.repeat(64),
    cpu: {} as NearTrustEvidence['cpu'],
    gpu: {} as NearTrustEvidence['gpu'],
    raw: {} as NearTrustEvidence['raw'],
  }
}

describe('fail-closed client protocol', () => {
  it('caps evidence at five minutes and rejects already expired evidence', () => {
    const now = Date.parse('2026-08-06T12:00:00Z')
    expect(capEvidenceExpiry('2026-08-06T13:00:00Z', now)).toBe('2026-08-06T12:05:00.000Z')
    expect(() => capEvidenceExpiry('2026-08-06T11:59:59Z', now)).toThrow(/expired/)
  })

  it('accepts the selected response shape and rejects model or metadata substitutions', () => {
    const valid = { id: 'chat-123', model: policy.model, choices: [{ message: { content: 'aa' } }] }
    expect(parseCompletionResponse(valid, policy).id).toBe('chat-123')
    expect(() => parseCompletionResponse({ ...valid, model: 'evil/model' }, policy)).toThrow(/model/)
    expect(() => parseCompletionResponse({ ...valid, prompt_text: 'leak' }, policy)).toThrow(/non-null/)
    expect(() => parseCompletionResponse({ ...valid, upstream_url: 'https://evil.test' }, policy)).toThrow(/Unexpected/)
  })

  it('authenticates the exact encrypted request and response bytes', () => {
    const seed = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
    const publicKey = bytesToHex(ed25519.getPublicKey(seed))
    const requestText = '{"ciphertext":"aa"}'
    const responseText = '{"ciphertext":"bb"}'
    const signedText = `${policy.model}:${sha256Hex(requestText)}:${sha256Hex(responseText)}`
    const signature = bytesToHex(ed25519.sign(textEncoder.encode(signedText), seed))
    const report = { text: signedText, signature, signing_address: publicKey, signing_algo: 'ed25519' }
    expect(verifyCompletionSignature(report, evidence(publicKey), policy, requestText, responseText).signer).toBe(publicKey)
    expect(() => verifyCompletionSignature(report, evidence(publicKey), policy, requestText, `${responseText} `)).toThrow(/exact request and response/)
  })
})
