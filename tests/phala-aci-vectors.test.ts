import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'
import {
  attestationStatement,
  canonicalize,
  checkRequestBodyHash,
  checkResponseBodyHash,
  checkSessionEvidence,
  computeKeysetDigest,
  computeReportData,
  computeSessionId,
  hashBody,
  jcsBytes,
  openE2eeChannel,
  receiptSigningBytes,
  reportDataSlot,
  requestAad,
  responseAad,
  verifyReceipt,
  verifyReportBinding,
  type ReceiptEnvelope,
  type ReportVerification,
  type WorkloadKeyset,
} from '../src/lib/phala-aci'
import { bytesToHex, hexToBytes, textDecoder, textEncoder } from '../src/lib/encoding'

/**
 * Byte-exact vectors from spec/test-vectors.md and spec/e2ee-v2-test-vectors.md
 * at private-ai-gateway commit 898f19f36978102aade8785632eb36f8d4459337.
 */

const RECEIPT_SEED = new Uint8Array(32).fill(0x02)
const E2EE_SEED = new Uint8Array(32).fill(0x03)
const RECEIPT_PUBLIC = '8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394'
const E2EE_PUBLIC = '5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22'
const NONCE = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
const KEYSET_DIGEST = 'sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371'
const SESSION_ID = '95ad1cb4dd25445808c2e9d116caf420b05703730b506395e8fc1ca6faeae28f'

const KEYSET: WorkloadKeyset = {
  tls_public_keys: [{ spki_sha256: 'c0'.repeat(32), domain: 'api.example.com' }],
  subject: 'dstack-app://example-app',
  receipt_signing_keys: [{ public_key: RECEIPT_PUBLIC, key_id: 'receipt-1', algo: 'ed25519' }],
  not_after: 1800000000,
  e2ee_public_keys: [{ key_id: 'e2ee-1', algo: 'x25519-aes-256-gcm-hkdf-sha256', public_key: E2EE_PUBLIC }],
}

const SESSION = {
  verifier_id: 'example/1',
  upstream_name: 'demo-upstream',
  expires_at: 1750003600,
  evidence: { digest: 'sha256:80d70e44d0ae1e829fd5f37c3ee4a60dfbea8d3aa18407ea3f34cf7ec91da34d', data: 'data:text/plain;base64,ZXhhbXBsZS1ldmlkZW5jZQ==' },
  established_at: 1750000000,
  endpoint: 'https://upstream.example.com',
  claims: {
    tee_attested: { status: 'asserted', source: 'hardware_proven', reason: 'example quote verified' },
    tcb_up_to_date: { status: 'unknown' },
    serving_software_known_good: { status: 'unknown' },
    os_known_good: { status: 'unknown' },
    model_weights_provenance: { status: 'unknown' },
    gpu_attested: { status: 'unknown' },
    extra: { tcb_status: 'UpToDate', gpu_arch: 'HOPPER' },
  },
  channel_binding: [{ type: 'tls_spki_sha256', spki_sha256: 'd1'.repeat(32), origin: 'https://upstream.example.com' }],
  api_version: 'aci/1',
}

const REQUEST_BODY = '{"messages":[{"content":"hi","role":"user"}],"model":"demo-model"}'
const RESPONSE_BODY = '{"choices":[],"id":"chatcmpl-123"}'
const REQUEST_HASH = 'sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b'
const RESPONSE_HASH = 'sha256:dedfffe5b14d031b8e2c01996d021a15293cb7c63b56be7e4be9e89b6f0a5f61'
const SIGNATURE = 'd5b005e093bde3b577faf270b7184b09e169cacb0ecb206b103bd2581f997db03da616175454b063323a23ac1dc68f1ce506c2a6eba8aa0561d5e724f0b80c03'

const RECEIPT: ReceiptEnvelope = {
  workload_keyset_digest: KEYSET_DIGEST,
  signature: SIGNATURE,
  served_at: 1750000000,
  receipt_id: 'rcpt-0001',
  model: 'demo-model',
  method: 'POST',
  key_id: 'receipt-1',
  event_log: [
    { type: 'request.received', body_hash: REQUEST_HASH },
    { type: 'request.forwarded', body_hash: REQUEST_HASH },
    { type: 'upstream.verified', session_id: SESSION_ID, result: 'verified', required: true, model_id: 'demo-model' },
    { type: 'response.returned', body_hash: RESPONSE_HASH },
  ],
  endpoint: '/v1/chat/completions',
  chat_id: 'chatcmpl-123',
  api_version: 'aci/1',
}

describe('spec/test-vectors.md', () => {
  it('fixed keys derive the published public keys', () => {
    expect(bytesToHex(ed25519.getPublicKey(RECEIPT_SEED))).toBe(RECEIPT_PUBLIC)
    expect(bytesToHex(x25519.getPublicKey(E2EE_SEED))).toBe(E2EE_PUBLIC)
  })

  it('1. workload keyset JCS form and digest (§3.1)', () => {
    expect(canonicalize(KEYSET)).toBe(
      '{"e2ee_public_keys":[{"algo":"x25519-aes-256-gcm-hkdf-sha256","key_id":"e2ee-1","public_key":"5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"}],"not_after":1800000000,"receipt_signing_keys":[{"algo":"ed25519","key_id":"receipt-1","public_key":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"}],"subject":"dstack-app://example-app","tls_public_keys":[{"domain":"api.example.com","spki_sha256":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"}]}',
    )
    expect(computeKeysetDigest(KEYSET)).toBe(KEYSET_DIGEST)
  })

  it('2. attestation statement and report_data (§3.2)', () => {
    expect(textDecoder.decode(attestationStatement(KEYSET_DIGEST, NONCE))).toBe(
      `{"keyset_digest":"${KEYSET_DIGEST}","nonce":"${NONCE}","purpose":"aci.report_data.v1"}`,
    )
    expect(computeReportData(KEYSET_DIGEST, NONCE)).toBe('df2174d28130852b413646a3786927b93e94c11d770268b65def8bdba45cb49e')
    expect(textDecoder.decode(attestationStatement(KEYSET_DIGEST, null))).toBe(
      `{"keyset_digest":"${KEYSET_DIGEST}","nonce":null,"purpose":"aci.report_data.v1"}`,
    )
    expect(computeReportData(KEYSET_DIGEST, undefined)).toBe('0633919ca3f00e97bafaa3304278eb22420cc3ff0d19f87dfca2d3f7508150bc')
    expect(bytesToHex(reportDataSlot('df2174d28130852b413646a3786927b93e94c11d770268b65def8bdba45cb49e'))).toBe(
      'df2174d28130852b413646a3786927b93e94c11d770268b65def8bdba45cb49e' + '00'.repeat(32),
    )
    expect(() => attestationStatement(KEYSET_DIGEST, NONCE.toUpperCase())).toThrow('64 lowercase hex')
    expect(() => attestationStatement(KEYSET_DIGEST.slice(0, -1), NONCE)).toThrow('keyset digest')
  })

  it('2. verifyReportBinding recomputes the chain from the served keyset', () => {
    const report = {
      api_version: 'aci/1',
      workload_keyset_digest: KEYSET_DIGEST,
      attestation: { tee_type: 'tdx', workload_keyset: KEYSET, report_data: 'df2174d28130852b413646a3786927b93e94c11d770268b65def8bdba45cb49e' },
    }
    // The vector keyset expires at 1800000000; 1790000000 keeps it inside the
    // 366-day lifetime bound while 1700000000 (below) does not.
    const now = 1790000000
    const verified = verifyReportBinding(report, NONCE, { now })
    expect(verified.ok).toBe(true)
    expect(verified.workloadKeysetDigest).toBe(KEYSET_DIGEST)
    expect(verified.keyset).toBe(KEYSET)
    expect(verified.checks.map((check) => check.name)).toEqual(['api_version', 'workload_keyset_digest', 'report_data', 'not_after', 'not_after_bound'])

    const failing = (mutated: typeof report, nonce = NONCE, options = { now }) =>
      verifyReportBinding(mutated, nonce, options).checks.filter((check) => !check.ok).map((check) => check.name)
    expect(failing(report, '11'.repeat(32))).toEqual(['report_data'])
    expect(failing({ ...report, workload_keyset_digest: 'sha256:' + '00'.repeat(32) })).toEqual(['workload_keyset_digest'])
    expect(failing({ ...report, attestation: { ...report.attestation, workload_keyset: { ...KEYSET, not_after: 1800000001 } } })).toEqual(['workload_keyset_digest', 'report_data'])
    expect(failing({ ...report, api_version: 'aci/2' })).toEqual(['api_version'])
    expect(failing(report, NONCE, { now: 1800000000 })).toEqual(['not_after'])
    expect(failing(report, NONCE, { now: 1700000000 })).toEqual(['not_after_bound'])
    expect(failing(report, NONCE, { now: 1700000000, maxKeysetLifetimeSeconds: 100000000 })).toEqual([])
    expect(() => verifyReportBinding(report, 'not-hex', { now })).toThrow('64 lowercase hex')
  })

  it('3. attested session id and evidence digest (§8)', () => {
    expect(canonicalize(SESSION)).toBe(
      '{"api_version":"aci/1","channel_binding":[{"origin":"https://upstream.example.com","spki_sha256":"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1","type":"tls_spki_sha256"}],"claims":{"extra":{"gpu_arch":"HOPPER","tcb_status":"UpToDate"},"gpu_attested":{"status":"unknown"},"model_weights_provenance":{"status":"unknown"},"os_known_good":{"status":"unknown"},"serving_software_known_good":{"status":"unknown"},"tcb_up_to_date":{"status":"unknown"},"tee_attested":{"reason":"example quote verified","source":"hardware_proven","status":"asserted"}},"endpoint":"https://upstream.example.com","established_at":1750000000,"evidence":{"data":"data:text/plain;base64,ZXhhbXBsZS1ldmlkZW5jZQ==","digest":"sha256:80d70e44d0ae1e829fd5f37c3ee4a60dfbea8d3aa18407ea3f34cf7ec91da34d"},"expires_at":1750003600,"upstream_name":"demo-upstream","verifier_id":"example/1"}',
    )
    expect(computeSessionId(SESSION)).toBe(SESSION_ID)
    expect(hashBody('example-evidence')).toBe(SESSION.evidence.digest)
    expect(checkSessionEvidence(SESSION.evidence)).toBe(true)
    expect(checkSessionEvidence({ ...SESSION.evidence, data: 'data:text/plain;base64,ZXhhbXBsZS1ldmlkZW5jZg==' })).toBe(false)
    expect(checkSessionEvidence({ ...SESSION.evidence, data: 'data:text/plain,example-evidence' })).toBe(false)
    expect(checkSessionEvidence({ digest: SESSION.evidence.digest })).toBe(false)
  })

  it('4. receipt signing input, signature, and body hashes (§7)', () => {
    expect(hashBody(REQUEST_BODY)).toBe(REQUEST_HASH)
    expect(hashBody(RESPONSE_BODY)).toBe(RESPONSE_HASH)
    const signingInput = receiptSigningBytes(RECEIPT)
    expect(textDecoder.decode(signingInput)).toBe(
      '{"api_version":"aci/1","chat_id":"chatcmpl-123","endpoint":"/v1/chat/completions","event_log":[{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.received"},{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.forwarded"},{"model_id":"demo-model","required":true,"result":"verified","session_id":"95ad1cb4dd25445808c2e9d116caf420b05703730b506395e8fc1ca6faeae28f","type":"upstream.verified"},{"body_hash":"sha256:dedfffe5b14d031b8e2c01996d021a15293cb7c63b56be7e4be9e89b6f0a5f61","type":"response.returned"}],"key_id":"receipt-1","method":"POST","model":"demo-model","receipt_id":"rcpt-0001","served_at":1750000000,"workload_keyset_digest":"sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371"}',
    )
    expect(bytesToHex(sha256(signingInput))).toBe('1bd328e6880a5a12b3915af95ea32111310e04ab9e21ac3d71ce268e33b965c9')
    expect(bytesToHex(ed25519.sign(signingInput, RECEIPT_SEED))).toBe(SIGNATURE)

    const verified = verifyReceipt(RECEIPT, KEYSET, KEYSET_DIGEST)
    expect(verified.ok).toBe(true)
    expect(verified.checks.map((check) => check.name)).toEqual(['signature', 'api_version', 'workload_keyset_digest'])
    expect(checkRequestBodyHash(verified.payload, REQUEST_BODY)).toBe(true)
    expect(checkResponseBodyHash(verified.payload, RESPONSE_BODY)).toBe(true)
    expect(checkResponseBodyHash(verified.payload, RESPONSE_BODY + '\n')).toBe(false)

    const failing = (document: ReceiptEnvelope, keyset = KEYSET, digest = KEYSET_DIGEST) =>
      verifyReceipt(document, keyset, digest).checks.filter((check) => !check.ok).map((check) => check.name)
    expect(failing({ ...RECEIPT, served_at: 1750000001 })).toEqual(['signature'])
    expect(failing({ ...RECEIPT, key_id: 'receipt-2' })).toEqual(['signature'])
    expect(failing(RECEIPT, { ...KEYSET, receipt_signing_keys: [{ ...KEYSET.receipt_signing_keys[0]!, algo: 'ecdsa-secp256k1' }] })).toEqual(['signature'])
    expect(failing({ ...RECEIPT, signature: SIGNATURE.slice(2) + 'zz' })).toEqual(['signature'])
    expect(failing({ ...RECEIPT, api_version: 'aci/0' })).toEqual(['signature', 'api_version'])
    expect(failing(RECEIPT, KEYSET, 'sha256:' + '00'.repeat(32))).toEqual(['workload_keyset_digest'])
  })

  it('canonicalizes any served encoding of the same document to the same bytes', () => {
    // RECEIPT above is written in reverse-sorted member order; this is the ascending one.
    const reordered = Object.fromEntries(Object.keys(RECEIPT).sort().map((key) => [key, RECEIPT[key]])) as ReceiptEnvelope
    expect(Object.keys(reordered)).not.toEqual(Object.keys(RECEIPT))
    expect(bytesToHex(receiptSigningBytes(reordered))).toBe(bytesToHex(receiptSigningBytes(RECEIPT)))
    expect(bytesToHex(jcsBytes(reordered))).toBe(bytesToHex(jcsBytes(RECEIPT)))
  })
})

describe('spec/e2ee-v2-test-vectors.md', () => {
  const ALGO = 'x25519-aes-256-gcm-hkdf-sha256'
  const context = { algo: ALGO, model: 'demo-model', nonce: NONCE, ts: 1750000000 }

  it('request and response field AAD bytes (e2ee-v2 §6)', () => {
    expect(textDecoder.decode(requestAad({ ...context, field: 'messages.0.content' }))).toBe(
      `{"algo":"${ALGO}","field":"messages.0.content","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":1750000000}`,
    )
    expect(textDecoder.decode(responseAad({ ...context, field: 'choices.0.message.content', id: 'chatcmpl-123' }))).toBe(
      `{"algo":"${ALGO}","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.response.v2","ts":1750000000}`,
    )
  })

  it('seals request fields the fixed service key can open with the e2ee-v2 §4 construction', async () => {
    const verification: ReportVerification = { ok: true, checks: [], workloadKeysetDigest: KEYSET_DIGEST, keyset: KEYSET }
    const channel = await openE2eeChannel(verification, { keyId: 'e2ee-1', algorithm: ALGO, publicKey: E2EE_PUBLIC })
    const sealed = await channel.seal({ model: 'demo-model', messages: [{ role: 'user', content: 'hi' }] })
    expect(Object.keys(sealed.headers).sort()).toEqual(['X-Client-Pub-Key', 'X-E2EE-Nonce', 'X-E2EE-Timestamp', 'X-E2EE-Version', 'X-Model-Pub-Key'])
    expect(sealed.headers['X-E2EE-Version']).toBe('2')
    expect(sealed.headers['X-Model-Pub-Key']).toBe(E2EE_PUBLIC)
    expect(sealed.headers['X-E2EE-Nonce']).toMatch(/^[0-9a-f]{64}$/)

    // Open the sealed field as the service would: ECDH with the fixed seed,
    // HKDF-SHA256 with the suite info string, AES-256-GCM under the AAD.
    const blob = hexToBytes((sealed.body.messages as Array<{ content: string }>)[0]!.content)
    expect(blob.length).toBe(32 + 12 + 'hi'.length + 16)
    const shared = x25519.getSharedSecret(E2EE_SEED, blob.slice(0, 32))
    const key = await crypto.subtle.importKey('raw', hkdf(sha256, shared, undefined, textEncoder.encode('aci.e2ee.v2.x25519'), 32), 'AES-GCM', false, ['decrypt'])
    const aad = requestAad({ algo: ALGO, model: 'demo-model', field: 'messages.0.content', nonce: sealed.headers['X-E2EE-Nonce']!, ts: Number(sealed.headers['X-E2EE-Timestamp']) })
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(32, 44), additionalData: aad }, key, blob.slice(44))
    expect(textDecoder.decode(plaintext)).toBe('hi')
    await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(32, 44), additionalData: requestAad({ ...context, field: 'messages.1.content', nonce: sealed.headers['X-E2EE-Nonce']!, ts: Number(sealed.headers['X-E2EE-Timestamp']) }) }, key, blob.slice(44))).rejects.toThrow()
  })
})
