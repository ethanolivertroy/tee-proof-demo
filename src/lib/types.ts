import type { AttestationReport as AciAttestationReport } from './phala-aci/types'
import type { ProviderId } from './policy'

interface BaseCompletionReceipt {
  provider: ProviderId
  model: string
  requestHash: string
  responseHash: string
  signer: string
  signature: string
  signedText: string
  verifiedAt: string
}

export interface NearCompletionReceipt extends BaseCompletionReceipt {
  provider: 'near-ai'
}

/**
 * A verified ACI receipt (spec/aci.md §7, §9.3). `requestHash` is
 * `request.received.body_hash` over the plaintext request the browser
 * restored; `responseHash` is `response.returned.body_hash` over the exact
 * encrypted wire response; `signer` is the keyset digest and key id the
 * signature resolved through; `signedText` is the JCS signing input.
 */
export interface PhalaCompletionReceipt extends BaseCompletionReceipt {
  provider: 'phala-cloud'
  receiptId: string
  workloadKeysetDigest: string
  /** Content address of the attested upstream session the receipt cites (§8). */
  sessionId: string
  /** Verified upstream origin recorded in that session (§8.2). */
  upstreamEndpoint: string
}

export type CompletionReceipt = NearCompletionReceipt | PhalaCompletionReceipt

export interface AttestationReport {
  model_name: string
  signing_algo: string
  signing_public_key: string
  signing_address: string
  request_nonce: string
  intel_quote: string
  nvidia_payload: string
  info: {
    tcb_info: {
      app_compose: string
      compose_hash: string
      device_id: string
      event_log: unknown[]
      mrtd: string
      os_image_hash: string
      rtmr0: string
      rtmr1: string
      rtmr2: string
      rtmr3: string
    }
  }
}

export interface CpuEvidence {
  quoteAuthentic: boolean
  quoteHash: string
  tcbStatus: string
  advisoryIds: string[]
  quoteType: string
  debugDisabled: boolean
  nonceBound: boolean
  signingKeyBound: boolean
  measurementsPinned: boolean
  composeManifestHashed: boolean
  composeBoundToQuote: boolean
  osImagePinned: boolean
  measurements: { mrtd: string; rtmr0: string; rtmr1: string; rtmr2: string; rtmr3: string }
}

export interface GpuEvidence {
  count: number
  models: string[]
  architecture: string
  jwtSignaturesValid: boolean
  tokensFresh: boolean
  nonceBound: boolean
  deviceTokensBoundToOverall: boolean
  secureBoot: boolean
  debugDisabled: boolean
  measurementsValid: boolean
  overallResult: boolean
  expiresAt: string
  sourceHash: string
  overallTokenHash: string
  deviceTokenHashes: Record<string, string>
  rawOverallToken: string
  rawDeviceTokens: Record<string, string>
}

interface BaseTrustEvidence {
  modelId: string
  provider: ProviderId
  protocol: 'near-e2ee-v2' | 'phala-aci-v2'
  verifiedAt: string
  expiresAt: string
  nonce: string
  model: string
  endpointLabel: string
  signingPublicKey: string
  policyDigest: string
}

export interface NearTrustEvidence extends BaseTrustEvidence {
  provider: 'near-ai'
  protocol: 'near-e2ee-v2'
  composeHash: string
  osImageHash: string
  cpu: CpuEvidence
  gpu: GpuEvidence
  raw: AttestationReport
}

/**
 * What the gateway verifier measured. Every value here was checked against the
 * pinned policy before it was returned; the assertions in
 * phala-verifier-core.ts and phala-dstack.ts are the evidence, so there are
 * no pass/fail flags to restate them.
 */
export interface PhalaGatewayEvidence {
  quoteHash: string
  tcbStatus: string
  advisoryIds: string[]
  quoteType: string
  workloadKeysetDigest: string
  sourceCommit: string
  appId: string
  composeHash: string
  kmsRootPublicKey: string
  e2eeAlgorithm: string
  e2eeKeyId: string
  e2eePublicKey: string
  receiptAlgorithm: string
  receiptKeyId: string
  receiptPublicKey: string
  /** SPKI digest the keyset lists for the endpoint hostname (§9.1 check 6). */
  tlsSpkiSha256: string
  measurements: { mrtd: string; rtmr0: string; rtmr1: string; rtmr2: string; rtmr3: string; mrConfigId: string }
}

export interface PhalaTrustEvidence extends BaseTrustEvidence {
  provider: 'phala-cloud'
  protocol: 'phala-aci-v2'
  gateway: PhalaGatewayEvidence
  raw: AciAttestationReport
}

export type TrustEvidence = NearTrustEvidence | PhalaTrustEvidence

export interface SignatureReport {
  text: string
  signature: string
  signing_address: string
  signing_algo: string
  signature_kind?: string
}

export interface CompletionResponse {
  id: string
  model: string
  choices: Array<{
    finish_reason?: string
    message: { role?: string; content?: string; reasoning_content?: string; reasoning?: string }
  }>
  metadata?: { weight_version: string }
}

export interface VerifiedCompletion {
  content: string
  receipt: CompletionReceipt
}
