import { getCollateralAndVerify } from '@phala/dcap-qvl'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, equalBytes, hexToBytes, textEncoder } from './encoding'
import { assert } from './guards'
import type { NearModelPolicy, WorkloadMeasurements } from './policy'
import type { AttestationReport, CpuEvidence } from './types'

const HEX_32 = /^[0-9a-f]{64}$/i

function normalizedHex(value: string): string {
  return value.replace(/^0x/i, '').toLowerCase()
}

function extractTdReport(verified: Awaited<ReturnType<typeof getCollateralAndVerify>>) {
  return verified.report.asTd10() ?? verified.report.asTd15()?.base ?? null
}

type TdReport = NonNullable<ReturnType<typeof extractTdReport>>

function verifyPinnedMeasurements(report: AttestationReport, td: TdReport, policy: NearModelPolicy) {
  const reported = report.info.tcb_info
  const measured = {
    mrtd: bytesToHex(td.mrTd),
    rtmr0: bytesToHex(td.rtMr0),
    rtmr1: bytesToHex(td.rtMr1),
    rtmr2: bytesToHex(td.rtMr2),
    rtmr3: bytesToHex(td.rtMr3),
  }

  const profile = policy.measurementProfiles.find((candidate) =>
    measured.mrtd === candidate.mrtd
    && normalizedHex(reported.mrtd) === candidate.mrtd
    && measured.rtmr0 === candidate.rtmr0
    && normalizedHex(reported.rtmr0) === candidate.rtmr0
    && measured.rtmr1 === candidate.rtmr1
    && normalizedHex(reported.rtmr1) === candidate.rtmr1
    && measured.rtmr2 === candidate.rtmr2
    && normalizedHex(reported.rtmr2) === candidate.rtmr2
    && measured.rtmr3 === candidate.rtmr3
    && normalizedHex(reported.rtmr3) === candidate.rtmr3
    && normalizedHex(reported.compose_hash) === candidate.composeHash
    && normalizedHex(reported.os_image_hash) === candidate.osImageHash,
  )
  assert(profile, 'Verified measurements do not match one complete approved workload profile')
  return { measured, profile }
}

function verifyComposeBinding(report: AttestationReport, td: TdReport, profile: WorkloadMeasurements): void {
  const tcb = report.info.tcb_info
  const computedHash = sha256(textEncoder.encode(tcb.app_compose))
  const configuredHash = hexToBytes(profile.composeHash)
  assert(equalBytes(computedHash, configuredHash), 'Compose manifest SHA-256 does not match the approved policy')
  assert(normalizedHex(tcb.compose_hash) === profile.composeHash, 'Reported compose hash is not approved')

  const expectedMrConfigId = concatBytes(Uint8Array.of(1), configuredHash, new Uint8Array(15))
  assert(equalBytes(td.mrConfigId, expectedMrConfigId), 'TDX mr_config_id does not bind the approved compose manifest')
}

export async function verifyCpuAttestation(
  report: AttestationReport,
  requestedNonce: string,
  policy: NearModelPolicy,
): Promise<CpuEvidence> {
  assert(HEX_32.test(requestedNonce), 'The client nonce must be 32 bytes')
  assert(report.request_nonce.toLowerCase() === requestedNonce.toLowerCase(), 'Attestation response nonce mismatch')
  assert(report.model_name === policy.model, `Unexpected model: ${report.model_name}`)
  assert(report.signing_algo.toLowerCase() === 'ed25519', 'The model did not return an Ed25519 key')
  assert(normalizedHex(report.signing_address) === normalizedHex(report.signing_public_key), 'Signing address and public key differ')
  assert(HEX_32.test(normalizedHex(report.signing_public_key)), 'Model signing key must be 32 bytes')

  const quoteBytes = hexToBytes(report.intel_quote)
  const verified = await getCollateralAndVerify(quoteBytes)
  assert(verified.status === 'UpToDate', `Intel TCB status is ${verified.status}`)
  const td = extractTdReport(verified)
  assert(td, 'Expected an Intel TDX quote')

  // The QVL rejects TDX debug mode by default. Check the TUD.DEBUG bit again
  // here so the evidence object is derived from the quote, not a UI assumption.
  const debugDisabled = (td.tdAttributes[0] & 0x01) === 0
  assert(debugDisabled, 'TDX debug mode is enabled')

  const expectedReportData = concatBytes(hexToBytes(report.signing_address), hexToBytes(requestedNonce))
  assert(equalBytes(td.reportData, expectedReportData), 'TDX report_data does not bind the model key and fresh nonce')

  const { measured: measurements, profile } = verifyPinnedMeasurements(report, td, policy)
  verifyComposeBinding(report, td, profile)

  return {
    quoteAuthentic: true,
    quoteHash: bytesToHex(sha256(quoteBytes)),
    tcbStatus: verified.status,
    advisoryIds: verified.advisory_ids,
    quoteType: verified.report.type,
    debugDisabled: true,
    nonceBound: true,
    signingKeyBound: true,
    measurementsPinned: true,
    composeManifestHashed: true,
    composeBoundToQuote: true,
    osImagePinned: true,
    measurements,
  }
}
