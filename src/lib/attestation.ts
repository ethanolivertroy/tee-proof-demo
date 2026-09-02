import { sha256 } from '@noble/hashes/sha2.js'
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'
import { bytesToHex, textEncoder } from './encoding'
import { asRecord, assert } from './guards'
import { accessHeaders, fetchJson } from './http'
import { NVIDIA_ISSUER, NVIDIA_JWKS, type NearModelPolicy } from './policy'
import type { AttestationReport, CpuEvidence, GpuEvidence } from './types'
import { runVerifierInWorker } from './verifier-worker'

function claimIsTrue(payload: JWTPayload, name: string): void {
  assert(payload[name] === true, `NVIDIA claim failed: ${name}`)
}

function verifyTokenTimes(payload: JWTPayload, label: string): number {
  const now = Math.floor(Date.now() / 1000)
  assert(typeof payload.iat === 'number', `${label} is missing iat`)
  assert(typeof payload.nbf === 'number', `${label} is missing nbf`)
  assert(typeof payload.exp === 'number', `${label} is missing exp`)
  assert(payload.iat <= now + 60, `${label} was issued in the future`)
  assert(payload.nbf <= now + 60, `${label} is not active yet`)
  assert(payload.exp > now - 60, `${label} is expired`)
  assert(payload.exp - payload.iat <= 7_200, `${label} validity window is unexpectedly long`)
  return payload.exp
}

function expectedSubmoduleDigest(payload: JWTPayload, deviceName: string): string {
  const submods = asRecord(payload.submods, 'NVIDIA overall token is missing submods')
  const binding = submods[deviceName]
  assert(Array.isArray(binding) && binding.length === 2 && binding[0] === 'DIGEST', `Missing digest binding for ${deviceName}`)
  const digest = binding[1]
  assert(Array.isArray(digest) && digest.length === 2 && digest[0] === 'SHA-256', `Unsupported digest binding for ${deviceName}`)
  assert(typeof digest[1] === 'string' && /^[0-9a-f]{64}$/i.test(digest[1]), `Invalid digest binding for ${deviceName}`)
  return digest[1].toLowerCase()
}

function verifyDeviceClaims(payload: JWTPayload, deviceName: string, nonce: string): void {
  assert(payload.eat_nonce === nonce, `NVIDIA nonce mismatch for ${deviceName}`)
  claimIsTrue(payload, 'x-nvidia-gpu-attestation-report-nonce-match')
  claimIsTrue(payload, 'x-nvidia-gpu-attestation-report-signature-verified')
  claimIsTrue(payload, 'x-nvidia-gpu-attestation-report-cert-chain-validated')
  claimIsTrue(payload, 'x-nvidia-gpu-attestation-report-parsed')
  claimIsTrue(payload, 'x-nvidia-gpu-driver-rim-signature-verified')
  claimIsTrue(payload, 'x-nvidia-gpu-driver-rim-cert-validated')
  claimIsTrue(payload, 'x-nvidia-gpu-driver-rim-schema-validated')
  claimIsTrue(payload, 'x-nvidia-gpu-driver-rim-measurements-available')
  claimIsTrue(payload, 'x-nvidia-gpu-vbios-rim-signature-verified')
  claimIsTrue(payload, 'x-nvidia-gpu-vbios-rim-cert-validated')
  claimIsTrue(payload, 'x-nvidia-gpu-vbios-rim-schema-validated')
  claimIsTrue(payload, 'x-nvidia-gpu-vbios-rim-measurements-available')
  claimIsTrue(payload, 'x-nvidia-gpu-vbios-index-no-conflict')
  claimIsTrue(payload, 'x-nvidia-gpu-arch-check')
  assert(payload.secboot === true, `NVIDIA secure boot failed for ${deviceName}`)
  assert(payload.dbgstat === 'disabled', `NVIDIA debug mode is enabled for ${deviceName}`)
  assert(payload.measres === 'success', `NVIDIA measurements failed for ${deviceName}`)
  assert(payload['x-nvidia-attestation-warning'] == null, `NVIDIA attestation warning for ${deviceName}`)
}

function verifyCpuInWorker(report: AttestationReport, requestedNonce: string, policy: NearModelPolicy): Promise<CpuEvidence> {
  return runVerifierInWorker(
    () => new Worker(new URL('./cpu-verifier.worker.ts', import.meta.url), { type: 'module' }),
    { report, requestedNonce, policy },
    'Intel quote verification',
  )
}

async function verifyGpuAttestation(
  report: AttestationReport,
  requestedNonce: string,
  policy: NearModelPolicy,
  accessToken: string,
): Promise<GpuEvidence> {
  const source = JSON.parse(report.nvidia_payload) as {
    nonce?: string
    arch?: string
    evidence_list?: unknown[]
  }
  const sourceNonce = String(source.nonce ?? '').toLowerCase()
  assert(sourceNonce === requestedNonce.toLowerCase(), 'NVIDIA evidence is not bound to the browser challenge')
  assert(source.arch === policy.gpuArchitecture, `Unexpected NVIDIA architecture: ${String(source.arch)}`)
  assert(Array.isArray(source.evidence_list) && source.evidence_list.length === policy.gpuCount, 'Unexpected NVIDIA evidence count')

  const bundle = await fetchJson('/api/nras', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...accessHeaders(accessToken) },
    body: report.nvidia_payload,
  })
  assert(Array.isArray(bundle) && bundle.length === 2, 'Unexpected NVIDIA attestation bundle')

  const overallEntry = bundle[0]
  const deviceEntries = bundle[1]
  assert(Array.isArray(overallEntry) && overallEntry[0] === 'JWT' && typeof overallEntry[1] === 'string', 'Missing NVIDIA overall JWT')
  assert(deviceEntries && typeof deviceEntries === 'object' && !Array.isArray(deviceEntries), 'Missing NVIDIA device JWTs')

  const jwks = createRemoteJWKSet(new URL(NVIDIA_JWKS))
  const overall = await jwtVerify(overallEntry[1], jwks, { issuer: NVIDIA_ISSUER, clockTolerance: 30 })
  assert(overall.payload.eat_nonce === sourceNonce, 'NVIDIA overall nonce mismatch')
  claimIsTrue(overall.payload, 'x-nvidia-overall-att-result')
  const expirations = [verifyTokenTimes(overall.payload, 'NVIDIA overall token')]

  const devices = Object.entries(deviceEntries as Record<string, unknown>)
  assert(devices.length === policy.gpuCount, 'NVIDIA device count does not match policy')
  const submods = asRecord(overall.payload.submods, 'NVIDIA overall token is missing device bindings')
  assert(Object.keys(submods).length === devices.length, 'NVIDIA overall token has an unexpected device set')

  const models: string[] = []
  const deviceTokenHashes: Record<string, string> = {}
  for (const [name, token] of devices) {
    assert(typeof token === 'string', `Invalid NVIDIA token for ${name}`)
    const actualDigest = bytesToHex(sha256(textEncoder.encode(token)))
    assert(actualDigest === expectedSubmoduleDigest(overall.payload, name), `NVIDIA device token is not bound to the overall verdict: ${name}`)
    deviceTokenHashes[name] = actualDigest

    const verified = await jwtVerify(token, jwks, { issuer: NVIDIA_ISSUER, clockTolerance: 30 })
    expirations.push(verifyTokenTimes(verified.payload, `NVIDIA token ${name}`))
    verifyDeviceClaims(verified.payload, name, sourceNonce)
    if (typeof verified.payload.hwmodel === 'string') models.push(verified.payload.hwmodel)
  }

  assert(models.length === policy.gpuCount, 'NVIDIA hardware model is missing from a device token')
  return {
    count: devices.length,
    models: [...new Set(models)],
    architecture: source.arch,
    jwtSignaturesValid: true,
    tokensFresh: true,
    nonceBound: true,
    deviceTokensBoundToOverall: true,
    secureBoot: true,
    debugDisabled: true,
    measurementsValid: true,
    overallResult: true,
    expiresAt: new Date(Math.min(...expirations) * 1000).toISOString(),
    sourceHash: bytesToHex(sha256(textEncoder.encode(report.nvidia_payload))),
    overallTokenHash: bytesToHex(sha256(textEncoder.encode(overallEntry[1]))),
    deviceTokenHashes,
    rawOverallToken: overallEntry[1],
    rawDeviceTokens: deviceEntries as Record<string, string>,
  }
}

export async function verifyAttestation(
  report: AttestationReport,
  requestedNonce: string,
  policy: NearModelPolicy,
  accessToken: string,
  onStage?: (stage: 'cpu' | 'gpu') => void,
): Promise<{ cpu: CpuEvidence; gpu: GpuEvidence }> {
  onStage?.('cpu')
  const cpu = await verifyCpuInWorker(report, requestedNonce, policy)
  onStage?.('gpu')
  const gpu = await verifyGpuAttestation(report, requestedNonce, policy, accessToken)
  return { cpu, gpu }
}
