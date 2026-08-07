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

export interface PhalaCompletionReceipt extends BaseCompletionReceipt {
  provider: 'phala-cloud'
  receiptId: string
  workloadId: string
  workloadKeysetDigest: string
  upstreamProviderType: string
  sessionId: string
  /**
   * Whether the signed cleartext hash also matched our re-serialization of the
   * decrypted body. Reserialization drift is expected, so this is a diagnostic
   * rather than a trust requirement; the wire hash check is the binding one.
   */
  cleartextResponseHashMatched: boolean
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

export interface PhalaGatewayEvidence {
  quoteAuthentic: boolean
  quoteHash: string
  tcbStatus: string
  advisoryIds: string[]
  quoteType: string
  debugDisabled: boolean
  nonceBound: boolean
  identityBound: boolean
  keysetDigestBound: boolean
  keysetEndorsementValid: boolean
  keysetFresh: boolean
  measurementsPinned: boolean
  eventLogReplayed: boolean
  composeBoundToQuote: boolean
  kmsIdentityCustodyValid: boolean
  sourceProvenanceMatched: boolean
  workloadId: string
  workloadKeysetDigest: string
  appId: string
  composeHash: string
  kmsRootPublicKey: string
  e2eeAlgorithm: string
  e2eeKeyId: string
  e2eePublicKey: string
  receiptAlgorithm: string
  receiptKeyId: string
  receiptPublicKey: string
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
