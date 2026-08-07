import { secp256k1 } from '@noble/curves/secp256k1.js'
import { describe, expect, it } from 'vitest'
import { assertResponseTransparency } from '../src/lib/phala-completion'
import { canonicalize, fromHex, verifyReceipt, verifyReportBinding, verifySignature } from '../src/lib/phala-aci'
import type { AttestationReport, Receipt, WorkloadKeyset } from '../src/lib/phala-aci/types'
import { verifyMeasuredSourceProvenance } from '../src/lib/phala-dstack'
import { getModelPolicy, isPhalaPolicy } from '../src/lib/policy'

const bytes32 = (value: bigint) => {
  const hex = value.toString(16).padStart(64, '0')
  return Uint8Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16))
}

const keyset = (publicKey: string): WorkloadKeyset => ({
  workload_identity: { public_key: { algo: 'ed25519', public_key: '11'.repeat(32) } },
  keyset_epoch: { version: 1, not_after: 4_102_444_800 },
  receipt_signing_keys: [{ key_id: 'receipt-1', algo: 'ed25519', public_key: publicKey }],
})

const receipt = (signatureValue: string): Receipt => ({
  api_version: 'aci/1',
  receipt_id: 'rcpt-0123456789abcdef01234567',
  workload_id: 'sha256:wrong',
  workload_keyset_digest: 'sha256:wrong',
  model: 'test/model',
  endpoint: '/v1/chat/completions',
  method: 'POST',
  served_at: 1,
  event_log: [],
  signature: { key_id: 'receipt-1', algo: 'ed25519', value: signatureValue },
} as Receipt)

describe('Phala ACI parser and signature hardening', () => {
  it('binds source provenance to the quote-bound measured Compose preimage', () => {
    const policy = getModelPolicy('phala-gpt-oss-20b')
    expect(isPhalaPolicy(policy)).toBe(true)
    if (!isPhalaPolicy(policy)) throw new Error('Expected Phala policy')
    const measured = (repository = policy.sourceRepository, commit = policy.sourceCommit) => JSON.stringify({
      docker_compose_file: [
        'services:',
        '  gateway:',
        '    environment:',
        `      - PRIVATE_AI_GATEWAY_REPO_URL=${repository}`,
        `      - PRIVATE_AI_GATEWAY_REPO_COMMIT=${commit}`,
      ].join('\n'),
    })

    expect(verifyMeasuredSourceProvenance(measured(), policy)).toEqual({
      sourceRepository: policy.sourceRepository,
      sourceCommit: policy.sourceCommit,
    })
    expect(() => verifyMeasuredSourceProvenance(measured('https://evil.test/repo.git'), policy)).toThrow('repository')
    expect(() => verifyMeasuredSourceProvenance(measured(policy.sourceRepository, '0'.repeat(40)), policy)).toThrow('commit')
    expect(() => verifyMeasuredSourceProvenance(JSON.stringify({
      docker_compose_file: `- PRIVATE_AI_GATEWAY_REPO_URL=${policy.sourceRepository}`,
      source_provenance: { repo_commit: policy.sourceCommit },
    }), policy)).toThrow('exactly one PRIVATE_AI_GATEWAY_REPO_COMMIT')
  })

  it('rejects signed, whitespace, and partial hex byte pairs', () => {
    expect([...fromHex('0x00ff')]).toEqual([0, 255])
    for (const malformed of ['1z', '+1', ' 1', '0x0g']) {
      expect(() => fromHex(malformed)).toThrow('invalid hex')
    }
    expect(() => fromHex('0xabc')).toThrow('odd length: 3 chars')
  })

  it('rejects integers outside the JavaScript safe range before JCS hashing', () => {
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe(String(Number.MAX_SAFE_INTEGER))
    expect(() => canonicalize(Number.MAX_SAFE_INTEGER + 1)).toThrow('safe integers')
    expect(() => canonicalize(Number.MIN_SAFE_INTEGER - 1)).toThrow('safe integers')
  })

  it('applies the same low-S policy to recoverable secp256k1 signatures', () => {
    const secretKey = secp256k1.utils.randomSecretKey()
    const publicKey = secp256k1.getPublicKey(secretKey, false)
    const message = new TextEncoder().encode('ACI recovery signature')
    const recovered = secp256k1.sign(message, secretKey, { format: 'recovered' })
    const recovery = recovered[0]!
    const compact = recovered.slice(1)
    const wire = Uint8Array.of(...compact, recovery)
    expect(verifySignature('ecdsa-secp256k1', publicKey, wire, message, 'test')).toBe(true)

    const s = BigInt(`0x${Buffer.from(compact.slice(32)).toString('hex')}`)
    const highCompact = Uint8Array.of(...compact.slice(0, 32), ...bytes32(secp256k1.Point.Fn.ORDER - s))
    const highWire = Uint8Array.of(...highCompact, recovery ^ 1)
    expect(verifySignature('ecdsa-secp256k1', publicKey, highWire, message, 'test')).toBe(false)
  })

  it('returns failed signature checks instead of throwing on malformed hex', () => {
    const receiptResult = verifyReceipt(receipt('zz'), keyset('1z'))
    expect(receiptResult.ok).toBe(false)
    expect(receiptResult.checks.find((check) => check.name === 'signature')).toMatchObject({ ok: false })

    const report = {
      workload_id: 'sha256:wrong',
      workload_keyset_digest: 'sha256:wrong',
      attestation: {
        workload_keyset: keyset('00'.repeat(32)),
        report_data: '00'.repeat(32),
        keyset_endorsement: { algo: 'ed25519', value: '1z' },
      },
    } as unknown as AttestationReport
    const reportResult = verifyReportBinding(report, 'nonce')
    expect(reportResult.ok).toBe(false)
    expect(reportResult.checks.find((check) => check.name === 'keyset_endorsement')).toMatchObject({ ok: false })
  })
})

describe('Phala completion receipt gates', () => {
  it('requires response modification evidence only when response hashes differ', () => {
    const base = receipt('00'.repeat(64))
    base.event_log = [
      { seq: 0, type: 'response.received', cleartext_hash: 'sha256:same' },
      { seq: 1, type: 'response.returned', cleartext_hash: 'sha256:same', wire_hash: 'sha256:same' },
    ]
    expect(() => assertResponseTransparency(base)).not.toThrow()

    base.event_log[1]!.wire_hash = 'sha256:encrypted'
    expect(() => assertResponseTransparency(base)).toThrow('transparency.response_modified')
    base.event_log.push({ seq: 2, type: 'transparency.response_modified' })
    expect(() => assertResponseTransparency(base)).not.toThrow()

    const relayed = receipt('00'.repeat(64))
    relayed.event_log = [
      { seq: 0, type: 'response.received', cleartext_hash: 'sha256:upstream' },
      { seq: 1, type: 'response.returned', cleartext_hash: 'sha256:rewritten', wire_hash: 'sha256:rewritten' },
    ]
    expect(() => assertResponseTransparency(relayed)).toThrow('transparency.response_modified')
    relayed.event_log.push({ seq: 2, type: 'transparency.response_modified' })
    expect(() => assertResponseTransparency(relayed)).not.toThrow()
  })
})
