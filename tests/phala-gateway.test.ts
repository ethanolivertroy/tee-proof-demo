import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256, sha384 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import type { VerifiedReport } from '@phala/dcap-qvl'
import { describe, expect, it } from 'vitest'
import { bytesToHex, concatBytes, hexToBytes, textEncoder } from '../src/lib/encoding'
import { computeKeysetDigest, computeReportData, reportDataSlot, type AttestationReport, type JcsValue, type WorkloadKeyset } from '../src/lib/phala-aci'
import { verifyPhalaGateway, type QuoteVerifier } from '../src/lib/phala-verifier-core'
import { getModelPolicy, isPhalaPolicy, type PhalaModelPolicy } from '../src/lib/policy'

/**
 * A synthetic aci/1 report shaped like the live Phala gateway's, with its own
 * KMS root, app key, keyset, Compose, and event log, verified under a policy
 * pinned to those values. The hardware root is replaced by an injected quote
 * verifier that returns the TD report the fixture describes, so every other
 * fail-closed check runs exactly as it does in the browser.
 */

function livePolicy(): PhalaModelPolicy {
  const policy = getModelPolicy('phala-gpt-oss-20b')
  if (!isPhalaPolicy(policy)) throw new Error('Expected the Phala policy')
  return policy
}

const LIVE = livePolicy()
const NOW = 1_790_000_000
const NONCE = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
const RUNTIME_EVENT_TYPE = 0x08000001
const COMMIT = 'd567f6b4c4d93e33037ea202db04db86a8ad881c'

const seed = (byte: number) => new Uint8Array(32).fill(byte)
const RECEIPT_SEED = seed(0x02)
const E2EE_SEED = seed(0x03)
const KMS_ROOT_SEED = seed(0x04)
const APP_KEY_SEED = seed(0x05)
const RECEIPT_PUBLIC = bytesToHex(ed25519.getPublicKey(RECEIPT_SEED))
const E2EE_PUBLIC = bytesToHex(x25519.getPublicKey(E2EE_SEED))
const KMS_ROOT_PUBLIC = bytesToHex(secp256k1.getPublicKey(KMS_ROOT_SEED, true))
const APP_ID = bytesToHex(new Uint8Array(20).fill(0xa1))
const TLS_SPKI = 'c0'.repeat(32)
const MR = (byte: number) => bytesToHex(new Uint8Array(48).fill(byte))

interface DstackEvent { imr: number; event_type: number; digest: string; event: string; event_payload: string }

function runtimeEvent(event: string, payload = ''): DstackEvent {
  const eventType = new Uint8Array(4)
  new DataView(eventType.buffer).setUint32(0, RUNTIME_EVENT_TYPE, true)
  const payloadBytes = payload.length === 0 ? new Uint8Array() : hexToBytes(payload)
  const digest = sha384(concatBytes(eventType, textEncoder.encode(':'), textEncoder.encode(event), textEncoder.encode(':'), payloadBytes))
  return { imr: 3, event_type: RUNTIME_EVENT_TYPE, digest: bytesToHex(digest), event, event_payload: payload }
}

function replayRtmr3(events: readonly DstackEvent[]): string {
  let current = new Uint8Array(48)
  for (const event of events) {
    if (event.imr !== 3) continue
    current = sha384(concatBytes(current, hexToBytes(event.digest)))
  }
  return bytesToHex(current)
}

/** dstack KMS signatures: recoverable secp256k1 over keccak256, recovery id last. */
function kmsSign(secret: Uint8Array, message: Uint8Array): string {
  const recovered = secp256k1.sign(keccak_256(message), secret, { prehash: false, format: 'recovered' })
  return bytesToHex(concatBytes(recovered.slice(1), Uint8Array.of(recovered[0]!)))
}

function custodyEntry(role: string, purpose: string, algo: string, publicKey: string, derivedSeed: Uint8Array): Record<string, JcsValue> {
  const kmsPublicKey = secp256k1.getPublicKey(derivedSeed, false)
  const appSignature = kmsSign(APP_KEY_SEED, textEncoder.encode(`${purpose}:${bytesToHex(secp256k1.getPublicKey(derivedSeed, true))}`))
  const rootSignature = kmsSign(KMS_ROOT_SEED, concatBytes(textEncoder.encode('dstack-kms-issued:'), hexToBytes(APP_ID), secp256k1.getPublicKey(APP_KEY_SEED, true)))
  return { role, purpose, algo, public_key: publicKey, path: `aci/${role}/v1`, kms_public_key: bytesToHex(kmsPublicKey), signature_chain: [appSignature, rootSignature] }
}

function composeDescriptor(commit = COMMIT, repository = LIVE.sourceRepository): string {
  return JSON.stringify({
    manifest_version: 2,
    name: 'gateway',
    runner: 'docker-compose',
    docker_compose_file: [
      'services:',
      '  gateway:',
      '    image: ghcr.io/dstack-tee/private-ai-gateway',
      '    environment:',
      `      - PRIVATE_AI_GATEWAY_REPO_URL=${repository}`,
      `      - PRIVATE_AI_GATEWAY_REPO_COMMIT=${commit}`,
      '',
    ].join('\n'),
    kms_enabled: true,
    gateway_enabled: true,
  })
}

interface TdReport {
  type: 'td10' | 'td15' | 'sgx'
  mrTd: Uint8Array
  rtMr0: Uint8Array
  rtMr1: Uint8Array
  rtMr2: Uint8Array
  rtMr3: Uint8Array
  mrConfigId: Uint8Array
  reportData: Uint8Array
  tdAttributes: Uint8Array
}

interface Fixture {
  report: AttestationReport
  keyset: WorkloadKeyset
  td: TdReport
  tcbStatus: string
  policy: PhalaModelPolicy
  nonce: string
  now: number
}

interface FixtureOptions {
  keyset?: (keyset: WorkloadKeyset) => void
  compose?: string
  events?: (events: DstackEvent[]) => void
  custody?: (custody: Record<string, JcsValue>[]) => void
}

/** Build a self-consistent report: every hook edits its part before the digests, replay, and policy are derived from it. */
function buildFixture(options: FixtureOptions = {}): Fixture {
  const keyset: WorkloadKeyset = {
    subject: null,
    not_after: NOW + 30 * 86_400,
    receipt_signing_keys: [{ key_id: LIVE.receiptKeyId, algo: 'ed25519', public_key: RECEIPT_PUBLIC }],
    e2ee_public_keys: [
      { key_id: 'dstack-kms-e2ee-v1', algo: 'secp256k1-aes-256-gcm-hkdf-sha256', public_key: bytesToHex(secp256k1.getPublicKey(seed(0x06), false)) },
      { key_id: LIVE.e2eeKeyId, algo: LIVE.e2eeAlgorithm, public_key: E2EE_PUBLIC },
    ],
    tls_public_keys: [
      { domain: 'tee.redpill.ai', spki_sha256: 'd1'.repeat(32) },
      { domain: LIVE.endpointLabel, spki_sha256: TLS_SPKI },
    ],
  }
  options.keyset?.(keyset)
  const compose = options.compose ?? composeDescriptor()
  const composeHash = bytesToHex(sha256(textEncoder.encode(compose)))
  const events: DstackEvent[] = [
    { imr: 0, event_type: 0x1, digest: 'e0'.repeat(48), event: '', event_payload: '' },
    runtimeEvent('system-preparing'),
    runtimeEvent('app-id', APP_ID),
    runtimeEvent('compose-hash', composeHash),
    runtimeEvent('instance-id', 'b7'.repeat(20)),
    runtimeEvent('boot-mr-done'),
    runtimeEvent('mr-kms', 'ab'.repeat(32)),
    runtimeEvent('os-image-hash', 'bd'.repeat(32)),
    runtimeEvent('key-provider', bytesToHex(textEncoder.encode('{"name":"kms","id":"00"}'))),
    runtimeEvent('system-ready'),
  ]
  options.events?.(events)
  const custody = [
    custodyEntry('receipt', 'aci.receipt.ed25519.v1', 'ed25519', RECEIPT_PUBLIC, seed(0x07)),
    custodyEntry('e2ee-secp256k1', 'aci.e2ee.v1', 'secp256k1-aes-256-gcm-hkdf-sha256', bytesToHex(secp256k1.getPublicKey(seed(0x06), false)), seed(0x08)),
    custodyEntry('e2ee-x25519', 'aci.e2ee.x25519.v1', LIVE.e2eeAlgorithm, E2EE_PUBLIC, seed(0x09)),
  ]
  options.custody?.(custody)

  const digest = computeKeysetDigest(keyset)
  const reportData = computeReportData(digest, NONCE)
  const td: TdReport = {
    type: 'td10',
    mrTd: hexToBytes(MR(0x10)),
    rtMr0: hexToBytes(MR(0x20)),
    rtMr1: hexToBytes(MR(0x21)),
    rtMr2: hexToBytes(MR(0x22)),
    rtMr3: hexToBytes(replayRtmr3(events)),
    mrConfigId: concatBytes(Uint8Array.of(0x01), hexToBytes(composeHash), new Uint8Array(15)),
    reportData: reportDataSlot(reportData),
    tdAttributes: hexToBytes('0000001000000000'),
  }
  const policy: PhalaModelPolicy = {
    ...LIVE,
    sourceCommit: COMMIT,
    appId: APP_ID,
    composeHash,
    kmsRootPublicKey: KMS_ROOT_PUBLIC,
    measurementProfiles: [{
      mrtd: MR(0x10),
      rtmr0: MR(0x20),
      rtmr1: MR(0x21),
      rtmr2: MR(0x22),
      rtmr3: replayRtmr3(events),
      mrConfigId: bytesToHex(td.mrConfigId),
    }],
  }
  const report: AttestationReport = {
    api_version: 'aci/1',
    workload_keyset_digest: digest,
    attestation: {
      tee_type: 'tdx',
      workload_keyset: keyset,
      report_data: reportData,
      source_provenance: { repo_url: LIVE.sourceRepository, repo_commit: COMMIT, image_digest: null, image_provenance: null },
      evidence: {
        quote: 'f1'.repeat(64),
        quote_report_data: bytesToHex(td.reportData),
        event_log: JSON.stringify(events),
        vm_config: '{"os_image_hash":"bdbd"}',
        app_compose: compose,
        key_custody: { provider: 'dstack-kms', keys: custody },
        downstream_tls_binding: { domain: LIVE.endpointLabel, spki_sha256: TLS_SPKI },
      },
    },
    service_capabilities: { supported_e2ee_versions: ['2'], serving: 'aggregator' },
  }
  return { report, keyset, td, tcbStatus: 'UpToDate', policy, nonce: NONCE, now: NOW }
}

function quoteVerifier(fixture: Pick<Fixture, 'td' | 'tcbStatus'>): QuoteVerifier {
  const { type, ...body } = fixture.td
  const report = { type, asTd10: () => (type === 'sgx' ? null : body), asTd15: () => (type === 'td15' ? { base: body } : null) }
  return () => Promise.resolve({ status: fixture.tcbStatus, advisory_ids: [], report } as unknown as VerifiedReport)
}

function verify(fixture: Fixture) {
  return verifyPhalaGateway(fixture.report, fixture.nonce, fixture.policy, { now: fixture.now, verifyQuote: quoteVerifier(fixture) })
}

const evidence = (fixture: Fixture) => fixture.report.attestation.evidence as Record<string, unknown>

describe('verifyPhalaGateway', () => {
  it('accepts a report whose every binding matches the pinned policy', async () => {
    const fixture = buildFixture()
    const { evidence: verified, expiresAt } = await verify(fixture)
    expect(expiresAt).toBe(new Date(fixture.keyset.not_after * 1000).toISOString())
    expect(verified).toEqual({
      quoteHash: bytesToHex(sha256(hexToBytes('f1'.repeat(64)))),
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      quoteType: 'td10',
      workloadKeysetDigest: fixture.report.workload_keyset_digest,
      sourceCommit: COMMIT,
      appId: APP_ID,
      composeHash: fixture.policy.composeHash,
      kmsRootPublicKey: KMS_ROOT_PUBLIC,
      e2eeAlgorithm: LIVE.e2eeAlgorithm,
      e2eeKeyId: LIVE.e2eeKeyId,
      e2eePublicKey: E2EE_PUBLIC,
      receiptAlgorithm: 'ed25519',
      receiptKeyId: LIVE.receiptKeyId,
      receiptPublicKey: RECEIPT_PUBLIC,
      tlsSpkiSha256: TLS_SPKI,
      measurements: fixture.policy.measurementProfiles[0],
    })
  })

  it('accepts a TD 1.5 quote through the same base report', async () => {
    const fixture = buildFixture()
    fixture.td.type = 'td15'
    await expect(verify(fixture)).resolves.toMatchObject({ evidence: { quoteType: 'td15' } })
    fixture.td.type = 'sgx'
    await expect(verify(fixture)).rejects.toThrow('not a supported TDX quote')
  })

  describe('denies', () => {
    const cases: Array<[string, (fixture: Fixture) => void, string | RegExp]> = [
      ['a stale nonce', (f) => { f.nonce = '11'.repeat(32) }, 'report binding failed: report_data'],
      ['a restated digest that disagrees with the served keyset', (f) => { f.report.workload_keyset_digest = 'sha256:' + '00'.repeat(32) }, 'workload_keyset_digest'],
      ['a keyset edited after the quote', (f) => { f.report.attestation.workload_keyset.e2ee_public_keys[1]!.public_key = '00'.repeat(32) }, 'workload_keyset_digest, report_data'],
      ['an expired keyset', (f) => { f.now = f.keyset.not_after }, 'report binding failed: not_after'],
      ['a foreign api_version', (f) => { f.report.api_version = 'aci/2' }, 'Unsupported Phala ACI report version'],
      ['a non-TDX tee_type', (f) => { f.report.attestation.tee_type = 'sev_snp' }, 'not reporting Intel TDX'],
      ['a service without E2EE v2', (f) => { f.report.service_capabilities = { supported_e2ee_versions: ['3'], serving: 'aggregator' } }, 'E2EE v2 is unavailable'],
      ['a direct service, which has no sessions to audit', (f) => { f.report.service_capabilities = { supported_e2ee_versions: ['2'], serving: 'direct' } }, 'not serving as an ACI aggregator'],
      ['an out-of-date platform TCB', (f) => { f.tcbStatus = 'OutOfDate' }, 'Intel TCB is not current: OutOfDate'],
      ['a software-hardening-needed TCB', (f) => { f.tcbStatus = 'SWHardeningNeeded' }, 'Intel TCB is not current'],
      ['a debuggable TD', (f) => { f.td.tdAttributes = hexToBytes('0100001000000000') }, 'debug mode is enabled'],
      ['a quote whose report-data slot is not the statement', (f) => { f.td.reportData = new Uint8Array(64) }, 'not bound to the TDX quote'],
      ['quote_report_data evidence that disagrees with the quote', (f) => { evidence(f).quote_report_data = '00'.repeat(64) }, 'report-data evidence disagrees'],
      ['an unpinned rtmr0', (f) => { f.policy.measurementProfiles = [{ ...f.policy.measurementProfiles[0]!, rtmr0: MR(0x99) }] }, 'measurements are not approved'],
      ['an unpinned mrConfigId', (f) => { f.policy.measurementProfiles = [{ ...f.policy.measurementProfiles[0]!, mrConfigId: MR(0x99) }] }, 'measurements are not approved'],
      ['an unapproved source commit', (f) => { f.policy.sourceCommit = 'aa65d64c191949b8df7b1ebe210f5b8f8a8e6b99' }, 'Measured source commit is not approved'],
      ['an unapproved source repository', (f) => { f.policy.sourceRepository = 'https://github.com/evil/private-ai-gateway.git' }, 'Measured source repository is not approved'],
      ['declared provenance that disagrees with the measured Compose', (f) => { f.report.attestation.source_provenance = { repo_url: LIVE.sourceRepository, repo_commit: '0'.repeat(40) } }, 'Declared source commit disagrees'],
      ['a report without declared provenance', (f) => { delete f.report.attestation.source_provenance }, 'no source provenance'],
      ['an unapproved dstack app id', (f) => { f.policy.appId = 'ff'.repeat(20) }, 'app id is not approved'],
      ['an unapproved KMS root', (f) => { f.policy.kmsRootPublicKey = bytesToHex(secp256k1.getPublicKey(seed(0x0a), true)) }, 'KMS root is not approved'],
      ['an unlisted E2EE key id', (f) => { f.policy.e2eeKeyId = 'dstack-kms-e2ee-v2' }, 'Approved E2EE key is missing or changed'],
      ['the secp256k1 E2EE entry under the approved id', (f) => { f.policy.e2eeKeyId = 'dstack-kms-e2ee-v1' }, 'Approved E2EE key is missing or changed'],
      ['an unlisted receipt key id', (f) => { f.policy.receiptKeyId = 'receipt-9' }, 'Approved receipt key is missing or changed'],
      ['a subject the policy did not pin', (f) => { f.policy.expectedSubject = 'dstack-app://gateway' }, 'Unexpected Phala workload subject'],
      ['a downstream TLS binding for another host', (f) => { evidence(f).downstream_tls_binding = { domain: 'tee.redpill.ai', spki_sha256: 'd1'.repeat(32) } }, 'downstream TLS binding is missing'],
      ['a downstream SPKI the keyset does not list', (f) => { evidence(f).downstream_tls_binding = { domain: LIVE.endpointLabel, spki_sha256: 'ee'.repeat(32) } }, 'TLS binding is not in the attested keyset'],
      ['missing quote evidence', (f) => { delete evidence(f).quote }, 'quote evidence is missing'],
      ['missing custody evidence', (f) => { delete evidence(f).key_custody }, 'Missing dstack KMS custody evidence'],
      ['a custody provider other than dstack-kms', (f) => { (evidence(f).key_custody as Record<string, unknown>).provider = 'local-key-provider' }, 'Missing dstack KMS custody evidence'],
    ]
    for (const [label, mutate, message] of cases) {
      it(label, async () => {
        const fixture = buildFixture()
        mutate(fixture)
        await expect(verify(fixture)).rejects.toThrow(message)
      })
    }
  })

  describe('denies keysets and evidence rebuilt around a tampered value', () => {
    it('an implausibly distant not_after', async () => {
      const fixture = buildFixture({ keyset: (keyset) => { keyset.not_after = NOW + 400 * 86_400 } })
      await expect(verify(fixture)).rejects.toThrow('report binding failed: not_after_bound')
    })

    it('a keyset member this protocol version does not define', async () => {
      const fixture = buildFixture({ keyset: (keyset) => { keyset.attestation_keys = [] } })
      await expect(verify(fixture)).rejects.toThrow('Unexpected Phala keyset member: attestation_keys')
    })

    it('a keyset with a subject the policy pins as absent', async () => {
      const fixture = buildFixture({ keyset: (keyset) => { keyset.subject = 'dstack-app://gateway' } })
      await expect(verify(fixture)).rejects.toThrow('Unexpected Phala workload subject')
      fixture.policy.expectedSubject = 'dstack-app://gateway'
      await expect(verify(fixture)).resolves.toBeDefined()
    })

    it('an approved receipt key entry that is not Ed25519', async () => {
      const fixture = buildFixture({ keyset: (keyset) => { keyset.receipt_signing_keys[0]!.algo = 'ecdsa-secp256k1' } })
      await expect(verify(fixture)).rejects.toThrow('Approved receipt key is missing or changed')
    })

    it('a Compose naming an unapproved commit', async () => {
      const fixture = buildFixture({ compose: composeDescriptor('0'.repeat(40)) })
      await expect(verify(fixture)).rejects.toThrow('Measured source commit is not approved')
    })

    it('a Compose preimage that no longer hashes to the measured compose-hash', async () => {
      const fixture = buildFixture()
      evidence(fixture).app_compose = `${evidence(fixture).app_compose as string} `
      await expect(verify(fixture)).rejects.toThrow('Compose preimage is not bound')
    })

    it('an event log that does not replay to the quoted rtmr3', async () => {
      const fixture = buildFixture()
      const events = JSON.parse(evidence(fixture).event_log as string) as DstackEvent[]
      events[2]!.event_payload = 'ff'.repeat(20)
      evidence(fixture).event_log = JSON.stringify(events)
      await expect(verify(fixture)).rejects.toThrow('does not replay to quote RTMR3')
    })

    it('a second app-id measured before system-ready', async () => {
      const fixture = buildFixture({ events: (events) => { events.splice(3, 0, runtimeEvent('app-id', 'ff'.repeat(20))) } })
      await expect(verify(fixture)).rejects.toThrow('Expected one measured app-id event')
    })

    it('a custody entry publishing a different key than the keyset', async () => {
      const fixture = buildFixture({ custody: (custody) => { custody[2]!.public_key = '00'.repeat(32) } })
      await expect(verify(fixture)).rejects.toThrow('e2ee-x25519 custody key does not match')
    })

    it('a custody chain for another derivation purpose', async () => {
      const fixture = buildFixture({ custody: (custody) => { custody[0]!.purpose = 'aci.e2ee.v1' } })
      await expect(verify(fixture)).rejects.toThrow('receipt custody purpose is not aci.receipt.ed25519.v1')
    })

    it('a custody chain missing for an approved key', async () => {
      const fixture = buildFixture({ custody: (custody) => { custody.splice(2, 1) } })
      await expect(verify(fixture)).rejects.toThrow('Missing e2ee-x25519 key custody evidence')
    })

    it('a custody chain signed by a different KMS root', async () => {
      const fixture = buildFixture({ custody: (custody) => {
        const kms = secp256k1.getPublicKey(seed(0x09), true)
        custody[2]!.signature_chain = [
          kmsSign(APP_KEY_SEED, textEncoder.encode(`aci.e2ee.x25519.v1:${bytesToHex(kms)}`)),
          kmsSign(seed(0x0b), concatBytes(textEncoder.encode('dstack-kms-issued:'), hexToBytes(APP_ID), secp256k1.getPublicKey(APP_KEY_SEED, true))),
        ]
      } })
      await expect(verify(fixture)).rejects.toThrow('custody chains name different roots')
    })

    it('a custody chain whose app key differs between roles', async () => {
      const fixture = buildFixture({ custody: (custody) => {
        const kms = secp256k1.getPublicKey(seed(0x09), true)
        const otherApp = seed(0x0c)
        custody[2]!.signature_chain = [
          kmsSign(otherApp, textEncoder.encode(`aci.e2ee.x25519.v1:${bytesToHex(kms)}`)),
          kmsSign(KMS_ROOT_SEED, concatBytes(textEncoder.encode('dstack-kms-issued:'), hexToBytes(APP_ID), secp256k1.getPublicKey(otherApp, true))),
        ]
      } })
      await expect(verify(fixture)).rejects.toThrow('custody chains name different app keys')
    })

    it('a custody signature that is not 65 bytes', async () => {
      const fixture = buildFixture({ custody: (custody) => {
        const chain = custody[0]!.signature_chain as string[]
        custody[0]!.signature_chain = [chain[0]!.slice(2), chain[1]!]
      } })
      await expect(verify(fixture)).rejects.toThrow('KMS signature must be 65 bytes')
    })
  })
})
