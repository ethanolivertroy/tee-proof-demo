/**
 * The reviewed Phala verifier profile: spec/aci.md §9.1 (cited from
 * ./phala-aci/index.ts) composed with the dstack `tdx` evidence policy. The
 * hardware check runs Intel DCAP QVL against Intel's collateral; the vendored
 * client does the keyset, statement, and expiry arithmetic; ./phala-dstack.ts
 * does provenance and custody. Every failure throws, so a caller cannot use a
 * report that did not pass all of it.
 */

import { getCollateralAndVerify, type VerifiedReport } from '@phala/dcap-qvl'
import { sha256Hex } from './crypto'
import { bytesToHex, equalBytes, hexToBytes } from './encoding'
import { assert, isRecord } from './guards'
import { verifyDstackEvidence, type ApprovedCustodyKey } from './phala-dstack'
import { reportDataSlot, verifyReportBinding, type AttestationReport, type KeysetKey } from './phala-aci'
import type { PhalaModelPolicy } from './policy'
import type { PhalaGatewayEvidence } from './types'

interface TdReport {
  type: 'td10' | 'td15'
  mrTd: Uint8Array
  rtMr0: Uint8Array
  rtMr1: Uint8Array
  rtMr2: Uint8Array
  rtMr3: Uint8Array
  mrConfigId: Uint8Array
  reportData: Uint8Array
  tdAttributes: Uint8Array
}

/** The dcap-qvl entry point, injectable so denial tests can run without Intel's collateral service. */
export type QuoteVerifier = (quote: Uint8Array) => Promise<VerifiedReport>

export interface VerifyPhalaGatewayOptions {
  /** Current time in Unix seconds; defaults to the local clock. */
  now?: number
  verifyQuote?: QuoteVerifier
}

// `Report.asTd10()` also returns the base of a TD 1.5 report, so the type tag
// comes from the report itself rather than from which accessor answered.
function extractTdReport(verified: VerifiedReport): TdReport | null {
  const type = verified.report.type
  if (type !== 'td10' && type !== 'td15') return null
  const body = verified.report.asTd10()
  return body ? { ...body, type } : null
}

function measurementsMatch(measured: PhalaGatewayEvidence['measurements'], policy: PhalaModelPolicy): boolean {
  return policy.measurementProfiles.some((profile) => Object.entries(profile).every(([key, value]) => measured[key as keyof typeof measured] === value))
}

/** §3.1: clients select keys by `algo`; this profile pins the exact `key_id` too. */
function selectKey(entries: unknown, keyId: string, algo: string, label: string): KeysetKey {
  assert(Array.isArray(entries), `Attested ${label} key list is missing`)
  const key = entries.find((entry) => isRecord(entry) && entry.key_id === keyId)
  assert(isRecord(key) && key.algo === algo && typeof key.public_key === 'string', `Approved ${label} key is missing or changed`)
  return key as unknown as KeysetKey
}

function failedChecks(checks: readonly { name: string; ok: boolean }[]): string {
  return checks.filter((check) => !check.ok).map((check) => check.name).join(', ')
}

export async function verifyPhalaGateway(
  report: AttestationReport,
  requestedNonce: string,
  policy: PhalaModelPolicy,
  options: VerifyPhalaGatewayOptions = {},
): Promise<{ evidence: PhalaGatewayEvidence; expiresAt: string }> {
  const now = options.now ?? Math.floor(Date.now() / 1000)
  const verifyQuote = options.verifyQuote ?? ((quote: Uint8Array) => getCollateralAndVerify(quote))

  assert(isRecord(report) && isRecord(report.attestation), 'Invalid Phala ACI report')
  assert(report.api_version === 'aci/1', 'Unsupported Phala ACI report version')
  assert(report.attestation.tee_type === 'tdx', 'Phala gateway is not reporting Intel TDX')
  const capabilities = report.service_capabilities
  assert(isRecord(capabilities) && Array.isArray(capabilities.supported_e2ee_versions) && capabilities.supported_e2ee_versions.includes('2'), 'Phala ACI E2EE v2 is unavailable')
  assert(capabilities.serving === 'aggregator', 'Phala gateway is not serving as an ACI aggregator')

  // §9.1 checks 2 and 3: keyset -> digest -> statement -> report_data, then expiry.
  const binding = verifyReportBinding(report, requestedNonce, { now })
  assert(binding.ok, `Phala ACI report binding failed: ${failedChecks(binding.checks)}`)
  const keyset = binding.keyset!
  const workloadKeysetDigest = binding.workloadKeysetDigest!
  assert((keyset.subject ?? null) === policy.expectedSubject, 'Unexpected Phala workload subject')

  // §9.1 check 1: the quote verifies to Intel's root with a current TCB, the
  // TD is not debuggable, and its report-data slot carries `report_data`.
  const evidence = report.attestation.evidence
  assert(isRecord(evidence) && typeof evidence.quote === 'string' && typeof evidence.quote_report_data === 'string', 'Phala TDX quote evidence is missing')
  const quote = hexToBytes(evidence.quote)
  const verifiedQuote = await verifyQuote(quote)
  assert(verifiedQuote.status === 'UpToDate', `Phala Intel TCB is not current: ${verifiedQuote.status}`)
  const td = extractTdReport(verifiedQuote)
  assert(td, 'Phala evidence is not a supported TDX quote')
  assert(td.tdAttributes.length > 0 && (td.tdAttributes[0]! & 1) === 0, 'Phala TDX debug mode is enabled')
  assert(equalBytes(td.reportData, reportDataSlot(report.attestation.report_data)), 'Phala ACI report digest is not bound to the TDX quote')
  assert(equalBytes(td.reportData, hexToBytes(evidence.quote_report_data)), 'Phala quote report-data evidence disagrees with the quote')

  const measurements = {
    mrtd: bytesToHex(td.mrTd),
    rtmr0: bytesToHex(td.rtMr0),
    rtmr1: bytesToHex(td.rtMr1),
    rtmr2: bytesToHex(td.rtMr2),
    rtmr3: bytesToHex(td.rtMr3),
    mrConfigId: bytesToHex(td.mrConfigId),
  }
  assert(measurementsMatch(measurements, policy), 'Phala gateway measurements are not approved')

  // §9.1 check 6 (E2EE half) and the receipt key the §9.3 checks will resolve.
  const e2eeKey = selectKey(keyset.e2ee_public_keys, policy.e2eeKeyId, policy.e2eeAlgorithm, 'E2EE')
  const receiptKey = selectKey(keyset.receipt_signing_keys, policy.receiptKeyId, policy.receiptAlgorithm, 'receipt')
  assert(hexToBytes(e2eeKey.public_key).length === 32, 'Phala X25519 public key length is invalid')
  assert(hexToBytes(receiptKey.public_key).length === 32, 'Phala Ed25519 receipt key length is invalid')

  // §9.1 checks 4 and 5: measured provenance and KMS custody for both keys.
  const approvedKeys: ApprovedCustodyKey[] = [
    { role: 'receipt', algo: receiptKey.algo, publicKey: receiptKey.public_key },
    { role: 'e2ee-x25519', algo: e2eeKey.algo, publicKey: e2eeKey.public_key },
  ]
  const dstack = verifyDstackEvidence(evidence, td.rtMr3, approvedKeys, report.attestation.source_provenance, policy)

  // §9.1 check 6 (TLS half): the SPKI the keyset lists for the hostname the
  // browser talks to is the one the evidence says this deployment pins.
  const downstream = evidence.downstream_tls_binding
  assert(isRecord(downstream) && downstream.domain === policy.endpointLabel && typeof downstream.spki_sha256 === 'string' && /^[0-9a-f]{64}$/.test(downstream.spki_sha256), 'Phala downstream TLS binding is missing')
  const tlsEntries = keyset.tls_public_keys
  assert(Array.isArray(tlsEntries) && tlsEntries.some((entry) => isRecord(entry) && entry.domain === policy.endpointLabel && entry.spki_sha256 === downstream.spki_sha256), 'Phala TLS binding is not in the attested keyset')

  return {
    expiresAt: new Date(keyset.not_after * 1000).toISOString(),
    evidence: {
      quoteHash: sha256Hex(quote),
      tcbStatus: verifiedQuote.status,
      advisoryIds: [...verifiedQuote.advisory_ids],
      quoteType: td.type,
      workloadKeysetDigest,
      sourceCommit: dstack.sourceCommit,
      appId: dstack.appId,
      composeHash: dstack.composeHash,
      kmsRootPublicKey: dstack.kmsRootPublicKey,
      e2eeAlgorithm: e2eeKey.algo,
      e2eeKeyId: e2eeKey.key_id,
      e2eePublicKey: e2eeKey.public_key,
      receiptAlgorithm: receiptKey.algo,
      receiptKeyId: receiptKey.key_id,
      receiptPublicKey: receiptKey.public_key,
      tlsSpkiSha256: downstream.spki_sha256,
      measurements,
    },
  }
}
