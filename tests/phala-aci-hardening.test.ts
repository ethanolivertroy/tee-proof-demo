import { describe, expect, it } from 'vitest'
import { canonicalize, fromBase64, fromHex, verifyReceipt, verifyReportBinding } from '../src/lib/phala-aci'
import type { AttestationReport, ReceiptEnvelope, WorkloadKeyset } from '../src/lib/phala-aci/types'
import { verifyMeasuredSourceProvenance } from '../src/lib/phala-dstack'
import { getModelPolicy, isPhalaPolicy } from '../src/lib/policy'

const keyset = (publicKey: string): WorkloadKeyset => ({
  not_after: 4_102_444_800,
  receipt_signing_keys: [{ key_id: 'receipt-1', algo: 'ed25519', public_key: publicKey }],
  e2ee_public_keys: [],
})

const receipt = (signature: string): ReceiptEnvelope => ({
  api_version: 'aci/1',
  receipt_id: 'rcpt-0123456789abcdef01234567',
  workload_keyset_digest: 'sha256:' + '00'.repeat(32),
  model: 'test/model',
  endpoint: '/v1/chat/completions',
  method: 'POST',
  served_at: 1,
  event_log: [],
  key_id: 'receipt-1',
  signature,
})

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
    expect(() => verifyMeasuredSourceProvenance('not json', policy)).toThrow('not valid JSON')
  })

  it('rejects signed, whitespace, and partial hex byte pairs', () => {
    expect([...fromHex('0x00ff')]).toEqual([0, 255])
    expect([...fromHex('')]).toEqual([])
    for (const malformed of ['1z', '+1', ' 1', '0x0g']) {
      expect(() => fromHex(malformed)).toThrow('invalid hex')
    }
    expect(() => fromHex('0xabc')).toThrow('odd length: 3 chars')
  })

  it('decodes only canonical standard base64', () => {
    expect(new TextDecoder().decode(fromBase64('ZXhhbXBsZS1ldmlkZW5jZQ=='))).toBe('example-evidence')
    for (const malformed of ['ZXhhbXBsZS1ldmlkZW5jZQ', 'ZXhh bXBs', 'ZXhhbXBsZS1ldmlkZW5jZQ===', 'ZXhh-XBs']) {
      expect(() => fromBase64(malformed)).toThrow('invalid base64')
    }
  })

  it('rejects integers outside the JavaScript safe range before JCS hashing', () => {
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe(String(Number.MAX_SAFE_INTEGER))
    expect(canonicalize(-0)).toBe('0')
    expect(() => canonicalize(Number.MAX_SAFE_INTEGER + 1)).toThrow('safe integers')
    expect(() => canonicalize(Number.MIN_SAFE_INTEGER - 1)).toThrow('safe integers')
    expect(() => canonicalize(1.5)).toThrow('safe integers')
  })

  it('returns failed signature checks instead of throwing on malformed hex', () => {
    const malformedSignature = verifyReceipt(receipt('zz'), keyset('00'.repeat(32)), 'sha256:' + '00'.repeat(32))
    expect(malformedSignature.ok).toBe(false)
    expect(malformedSignature.checks.find((check) => check.name === 'signature')).toMatchObject({ ok: false, detail: expect.stringContaining('malformed') })

    const malformedKey = verifyReceipt(receipt('00'.repeat(64)), keyset('1z'), 'sha256:' + '00'.repeat(32))
    expect(malformedKey.ok).toBe(false)
    expect(malformedKey.checks.find((check) => check.name === 'signature')).toMatchObject({ ok: false })

    const unknownKey = verifyReceipt({ ...receipt('00'.repeat(64)), key_id: 'receipt-9' }, keyset('00'.repeat(32)), 'sha256:' + '00'.repeat(32))
    expect(unknownKey.checks.find((check) => check.name === 'signature')).toMatchObject({ ok: false, detail: expect.stringContaining('not in receipt_signing_keys') })
  })

  it('fails every binding check when the served keyset is not an object', () => {
    for (const workload_keyset of [null, 'keyset', [1, 2, 3], 42]) {
      const report = {
        api_version: 'aci/1',
        workload_keyset_digest: 'sha256:' + '00'.repeat(32),
        attestation: { tee_type: 'tdx', workload_keyset, report_data: '00'.repeat(32) },
      } as unknown as AttestationReport
      const result = verifyReportBinding(report, '11'.repeat(32), { now: 1 })
      expect(result.ok).toBe(false)
      expect(result.keyset).toBeUndefined()
      expect(result.workloadKeysetDigest).toBeUndefined()
      expect(result.checks.filter((check) => !check.ok).map((check) => check.name)).toEqual([
        'workload_keyset_digest', 'report_data', 'not_after', 'not_after_bound',
      ])
    }
  })

  it('rejects a keyset without an integer not_after', () => {
    const report = {
      api_version: 'aci/1',
      workload_keyset_digest: 'sha256:' + '00'.repeat(32),
      attestation: { tee_type: 'tdx', workload_keyset: { ...keyset('00'.repeat(32)), not_after: '4102444800' }, report_data: '00'.repeat(32) },
    } as unknown as AttestationReport
    const result = verifyReportBinding(report, '11'.repeat(32), { now: 1 })
    expect(result.checks.filter((check) => !check.ok).map((check) => check.name)).toContain('not_after')
    expect(result.checks.filter((check) => !check.ok).map((check) => check.name)).toContain('not_after_bound')
  })
})
