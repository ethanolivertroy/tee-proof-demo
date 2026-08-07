import { getCollateralAndVerify } from '@phala/dcap-qvl'
import { sha256Hex } from './crypto'
import { bytesToHex, concatBytes, equalBytes, hexToBytes } from './encoding'
import { assert } from './guards'
import { verifyDstackEvidence } from './phala-dstack'
import { verifyReportBinding, type AttestationReport as AciAttestationReport, type JcsValue } from './phala-aci'
import type { PhalaModelPolicy } from './policy'
import type { PhalaGatewayEvidence } from './types'

interface TdReport {
  type: 'TD10' | 'TD15'
  mrTd: Uint8Array
  rtMr0: Uint8Array
  rtMr1: Uint8Array
  rtMr2: Uint8Array
  rtMr3: Uint8Array
  mrConfigId: Uint8Array
  reportData: Uint8Array
  tdAttributes: Uint8Array
}

interface E2eeKey {
  key_id: string
  algo: string
  public_key: string
}

interface PhalaWireReport extends AciAttestationReport {
  service_capabilities?: { supported_e2ee_versions?: JcsValue; [key: string]: JcsValue | undefined }
  attestation: AciAttestationReport['attestation'] & {
    vendor?: unknown
    tee_type?: unknown
    evidence?: unknown
  }
}

interface TdBody extends Omit<TdReport, 'type'> {}

interface QuoteReportView {
  asTd10(): TdBody | null
  asTd15(): { base: TdBody } | null
}

function extractTdReport(report: unknown): TdReport | null {
  if (!report || typeof report !== 'object' || !('asTd10' in report) || !('asTd15' in report)) return null
  const view = report as QuoteReportView
  const td10 = view.asTd10()
  if (td10) return { ...td10, type: 'TD10' }
  const td15 = view.asTd15()?.base
  return td15 ? { ...td15, type: 'TD15' } : null
}

function measurementsMatch(td: TdReport, policy: PhalaModelPolicy): boolean {
  const measured = {
    mrtd: bytesToHex(td.mrTd),
    rtmr0: bytesToHex(td.rtMr0),
    rtmr1: bytesToHex(td.rtMr1),
    rtmr2: bytesToHex(td.rtMr2),
    rtmr3: bytesToHex(td.rtMr3),
    mrConfigId: bytesToHex(td.mrConfigId),
  }
  return policy.measurementProfiles.some((profile) => Object.entries(profile).every(([key, value]) => measured[key as keyof typeof measured] === value))
}

function selectKey(entries: unknown, keyId: string, algo: string, label: string): E2eeKey {
  assert(Array.isArray(entries), `Attested ${label} key list is missing`)
  const key = entries.find((entry) => entry && typeof entry === 'object' && (entry as Record<string, unknown>).key_id === keyId) as Record<string, unknown> | undefined
  assert(key && key.algo === algo && typeof key.public_key === 'string', `Approved ${label} key is missing or changed`)
  return key as unknown as E2eeKey
}

export async function verifyPhalaGateway(
  report: AciAttestationReport,
  requestedNonce: string,
  policy: PhalaModelPolicy,
): Promise<{ evidence: PhalaGatewayEvidence; expiresAt: string }> {
  const wire = report as PhalaWireReport
  assert(wire.api_version === 'aci/1', 'Unsupported Phala ACI report version')
  assert(wire.attestation.tee_type === 'tdx', 'Phala gateway is not reporting Intel TDX')
  assert(wire.workload_id === policy.workloadId, `Phala workload is not approved: ${wire.workload_id}`)
  assert((wire.attestation.workload_keyset.workload_identity.subject ?? null) === policy.expectedSubject, 'Unexpected Phala workload subject')
  const capabilities = wire.service_capabilities
  assert(Array.isArray(capabilities?.supported_e2ee_versions) && capabilities.supported_e2ee_versions.includes('2'), 'Phala ACI E2EE v2 is unavailable')

  const binding = verifyReportBinding(report, requestedNonce, { trustPlatformClock: true })
  assert(binding.ok, `Phala ACI report binding failed: ${binding.checks.filter((check) => !check.ok).map((check) => check.name).join(', ')}`)
  assert(binding.workloadId === policy.workloadId, 'Derived Phala workload id is not approved')

  const evidence = wire.attestation.evidence as Record<string, unknown>
  assert(evidence && typeof evidence.quote === 'string' && typeof evidence.quote_report_data === 'string', 'Phala TDX quote evidence is missing')
  const verifiedQuote = await getCollateralAndVerify(hexToBytes(evidence.quote))
  assert(verifiedQuote.status === 'UpToDate', `Phala Intel TCB is not current: ${verifiedQuote.status}`)
  const td = extractTdReport(verifiedQuote.report)
  assert(td, 'Phala evidence is not a supported TDX quote')
  assert(td.tdAttributes[0] != null && (td.tdAttributes[0] & 1) === 0, 'Phala TDX debug mode is enabled')

  const expectedReportData = concatBytes(hexToBytes(wire.attestation.report_data), new Uint8Array(32))
  assert(equalBytes(td.reportData, expectedReportData), 'Phala ACI report digest is not bound to the TDX quote')
  assert(equalBytes(td.reportData, hexToBytes(evidence.quote_report_data)), 'Phala quote report-data evidence disagrees with the quote')
  assert(measurementsMatch(td, policy), 'Phala gateway measurements are not approved')

  const keyset = wire.attestation.workload_keyset
  const identityPublicKey = keyset.workload_identity.public_key.public_key
  const dstack = verifyDstackEvidence(evidence, identityPublicKey, td.rtMr3, policy)

  const e2eeKey = selectKey(keyset.e2ee_public_keys, policy.e2eeKeyId, policy.e2eeAlgorithm, 'E2EE')
  const receiptKey = selectKey(keyset.receipt_signing_keys, policy.receiptKeyId, policy.receiptAlgorithm, 'receipt')
  assert(hexToBytes(e2eeKey.public_key).length === 32, 'Phala X25519 public key length is invalid')
  assert(hexToBytes(receiptKey.public_key).length === 32, 'Phala Ed25519 receipt key length is invalid')

  const tlsEntries = keyset.tls_public_keys
  const downstream = evidence.downstream_tls_binding as Record<string, unknown>
  assert(Array.isArray(tlsEntries) && downstream?.domain === policy.endpointLabel && typeof downstream.spki_sha256 === 'string', 'Phala downstream TLS binding is missing')
  assert(tlsEntries.some((entry) => entry && typeof entry === 'object' && (entry as Record<string, unknown>).domain === policy.endpointLabel && (entry as Record<string, unknown>).spki_sha256 === downstream.spki_sha256), 'Phala TLS binding is not in the attested keyset')

  const freshness = wire.attestation.freshness
  const epoch = keyset.keyset_epoch
  assert(typeof freshness?.stale_after === 'number' && typeof epoch.not_after === 'number', 'Phala report expiry is missing')
  const expiresAtSeconds = Math.min(freshness.stale_after, epoch.not_after)
  assert(expiresAtSeconds * 1000 > Date.now(), 'Phala trust evidence is expired')

  return {
    expiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
    evidence: {
      quoteAuthentic: true,
      quoteHash: sha256Hex(hexToBytes(evidence.quote)),
      tcbStatus: verifiedQuote.status,
      advisoryIds: [...verifiedQuote.advisory_ids],
      quoteType: td.type,
      debugDisabled: true,
      nonceBound: true,
      identityBound: true,
      keysetDigestBound: true,
      keysetEndorsementValid: true,
      keysetFresh: true,
      measurementsPinned: true,
      eventLogReplayed: true,
      composeBoundToQuote: true,
      kmsIdentityCustodyValid: true,
      sourceProvenanceMatched: dstack.sourceRepository.replace(/\.git$/u, '') === policy.sourceRepository.replace(/\.git$/u, '')
        && dstack.sourceCommit === policy.sourceCommit,
      workloadId: binding.workloadId,
      workloadKeysetDigest: binding.workloadKeysetDigest,
      appId: dstack.appId,
      composeHash: dstack.composeHash,
      kmsRootPublicKey: dstack.kmsRootPublicKey,
      e2eeAlgorithm: e2eeKey.algo,
      e2eeKeyId: e2eeKey.key_id,
      e2eePublicKey: e2eeKey.public_key,
      receiptAlgorithm: receiptKey.algo,
      receiptKeyId: receiptKey.key_id,
      receiptPublicKey: receiptKey.public_key,
      measurements: {
        mrtd: bytesToHex(td.mrTd),
        rtmr0: bytesToHex(td.rtMr0),
        rtmr1: bytesToHex(td.rtMr1),
        rtmr2: bytesToHex(td.rtMr2),
        rtmr3: bytesToHex(td.rtMr3),
        mrConfigId: bytesToHex(td.mrConfigId),
      },
    },
  }
}
