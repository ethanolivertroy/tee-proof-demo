export type ProviderId = 'near-ai' | 'phala-cloud'

export interface WorkloadMeasurements {
  mrtd: string
  rtmr0: string
  rtmr1: string
  rtmr2: string
  rtmr3: string
  composeHash: string
  osImageHash: string
}

export interface PhalaGatewayMeasurements {
  mrtd: string
  rtmr0: string
  rtmr1: string
  rtmr2: string
  rtmr3: string
  mrConfigId: string
}

/** One row of the verification checklist the UI renders for a policy. */
export interface TrustStep {
  label: string
  detail: string
}

interface BaseModelPolicy {
  id: string
  label: string
  model: string
  endpointLabel: string
  provider: ProviderId
  providerLabel: string
  capturedAt: string
  /** Provider copy for the verification checklist, in completion order. */
  steps: readonly TrustStep[]
}

export interface NearModelPolicy extends BaseModelPolicy {
  provider: 'near-ai'
  protocol: 'near-e2ee-v2'
  gpuArchitecture: 'HOPPER'
  gpuCount: number
  measurementProfiles: readonly WorkloadMeasurements[]
}

export interface PhalaModelPolicy extends BaseModelPolicy {
  provider: 'phala-cloud'
  protocol: 'phala-aci-v2'
  workloadId: string
  /** ACI workload identity subject the gateway must present; null pins "no subject". */
  expectedSubject: string | null
  e2eeAlgorithm: 'x25519-aes-256-gcm-hkdf-sha256'
  e2eeKeyId: string
  receiptAlgorithm: 'ed25519'
  receiptKeyId: string
  sourceRepository: string
  sourceCommit: string
  appId: string
  composeHash: string
  kmsRootPublicKey: string
  requiredUpstreamProviderType: 'phala-direct'
  measurementProfiles: readonly PhalaGatewayMeasurements[]
}

export type ModelPolicy = NearModelPolicy | PhalaModelPolicy

const NEAR_COMMON = {
  mrtd: 'b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217',
  rtmr0: 'bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590',
  rtmr1: 'c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc',
  rtmr2: '564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135',
  osImageHash: '9b69bb1698bacbb6985409a2c272bcb892e09cdcea63d5399c6768b67d3ff677',
} as const

const NEAR_SHARED_PROFILE: WorkloadMeasurements = {
  ...NEAR_COMMON,
  rtmr3: '18c28d262ab4733031c19fa1af233686e227a789955ba9dba2065b398c9f5dbfb76133d751dac412540dc5ac992b1b73',
  composeHash: '66007399f064f058af68771c552bcae150c9f88622305631b5141da1aa2f7b7e',
}

const DEEPSEEK_PROFILE: WorkloadMeasurements = {
  ...NEAR_COMMON,
  rtmr3: 'b59915c0d50b09151f1e7fd6d6b571feded8e45eab874fffdcbd1e0341fb60eb25e9a07404a5adcc918ad684564a30ea',
  composeHash: 'd98a2568546afce9ab53f7eb4d4b2058e5497e1efd05a8ad0934793043240ed7',
}

const PHALA_GATEWAY_PROFILE: PhalaGatewayMeasurements = {
  mrtd: 'f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077',
  rtmr0: 'd6118f0eeb30e9d9178d2b9106dddd002d979b6fa79bdec415051afae2021384c29a32d2f6454fa369617598378ffb5e',
  rtmr1: '07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c',
  rtmr2: 'a2a58c9a959a4fa44bd6da0c97a2270c051faf12084cfe91ae900e4fdff6cdd4f69a82005e04ee920f231497894d677f',
  rtmr3: '58512f7be22b1dbd1c509e6aa0ad98ad2b5f1ede285355c0f97ebfa119f8538c4163d9d0ae347abb4d7bc557889b20aa',
  mrConfigId: '014496101140734539fb1e72c22252a0ba9992e3822b64d333a2452357a4adf0bb000000000000000000000000000000',
}

const NEAR_GPU_ARCHITECTURE = 'HOPPER'
const NEAR_GPU_COUNT = 8

export const MODEL_POLICIES = {
  'deepseek-v4-flash': {
    id: 'deepseek-v4-flash',
    label: 'DeepSeek V4 Flash',
    model: 'deepseek-ai/DeepSeek-V4-Flash',
    endpointLabel: 'dsv4-flash.completions.near.ai',
    provider: 'near-ai',
    providerLabel: 'NEAR AI Cloud',
    protocol: 'near-e2ee-v2',
    capturedAt: '2026-08-02',
    gpuArchitecture: NEAR_GPU_ARCHITECTURE,
    gpuCount: NEAR_GPU_COUNT,
    measurementProfiles: [NEAR_SHARED_PROFILE, DEEPSEEK_PROFILE],
    steps: [
      { label: 'Fresh challenge', detail: '32-byte browser nonce' },
      { label: 'Intel TDX', detail: 'Quote, debug state, and measurements' },
      { label: 'NVIDIA GPU', detail: `${NEAR_GPU_COUNT} ${NEAR_GPU_ARCHITECTURE.toLowerCase()} devices, signed verdicts` },
      { label: 'Model key', detail: 'Bound to nonce and approved workload' },
    ],
  },
  'phala-gpt-oss-20b': {
    id: 'phala-gpt-oss-20b',
    label: 'GPT-OSS 20B',
    model: 'openai/gpt-oss-20b',
    endpointLabel: 'inference.phala.com',
    provider: 'phala-cloud',
    providerLabel: 'Phala Cloud',
    protocol: 'phala-aci-v2',
    capturedAt: '2026-08-06',
    steps: [
      { label: 'Fresh challenge', detail: '32-byte browser nonce' },
      { label: 'Intel TDX', detail: 'Gateway quote, event log, and measurements' },
      { label: 'dstack + KMS', detail: 'Measured source, Compose, and key custody' },
      { label: 'Gateway keys', detail: 'E2EE and receipt keys bound to quote' },
    ],
    workloadId: 'sha256:3def476b72026924f9d88f7b339b2e211553fc2486c6a974d5f330162f183eda',
    expectedSubject: null,
    e2eeAlgorithm: 'x25519-aes-256-gcm-hkdf-sha256',
    e2eeKeyId: 'dstack-kms-e2ee-x25519-v1',
    receiptAlgorithm: 'ed25519',
    receiptKeyId: 'dstack-kms-receipt-ed25519-v1',
    sourceRepository: 'https://github.com/Dstack-TEE/private-ai-gateway.git',
    sourceCommit: 'aa65d64c191949b8df7b1ebe210f5b8f8a8e6b99',
    appId: 'fdb7a14e5a6675f752e2cb69c9067a98ca402918',
    composeHash: '4496101140734539fb1e72c22252a0ba9992e3822b64d333a2452357a4adf0bb',
    kmsRootPublicKey: '0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1',
    requiredUpstreamProviderType: 'phala-direct',
    measurementProfiles: [PHALA_GATEWAY_PROFILE],
  },
} as const satisfies Record<string, ModelPolicy>

export type ModelId = keyof typeof MODEL_POLICIES
export const DEFAULT_MODEL_ID: ModelId = 'deepseek-v4-flash'
export const MODEL_OPTIONS = Object.values(MODEL_POLICIES)

export function isModelId(value: string): value is ModelId {
  return Object.hasOwn(MODEL_POLICIES, value)
}

export function getModelPolicy(value: string): ModelPolicy {
  if (!isModelId(value)) throw new Error(`Model policy is not approved: ${value}`)
  return MODEL_POLICIES[value]
}

export function isNearPolicy(policy: ModelPolicy): policy is NearModelPolicy {
  return policy.protocol === 'near-e2ee-v2'
}

export function isPhalaPolicy(policy: ModelPolicy): policy is PhalaModelPolicy {
  return policy.protocol === 'phala-aci-v2'
}

function canonicalNearMeasurements(measurements: WorkloadMeasurements): string {
  return [measurements.mrtd, measurements.rtmr0, measurements.rtmr1, measurements.rtmr2, measurements.rtmr3, measurements.composeHash, measurements.osImageHash].join('\n')
}

function canonicalPhalaMeasurements(measurements: PhalaGatewayMeasurements): string {
  return [measurements.mrtd, measurements.rtmr0, measurements.rtmr1, measurements.rtmr2, measurements.rtmr3, measurements.mrConfigId].join('\n')
}

export function canonicalPolicyText(policy: ModelPolicy): string {
  const common = ['tee-proof-demo-policy-v2', policy.id, policy.provider, policy.protocol, policy.model, policy.endpointLabel]
  if (isNearPolicy(policy)) {
    return [...common, policy.gpuArchitecture, String(policy.gpuCount), ...policy.measurementProfiles.map(canonicalNearMeasurements)].join('\n')
  }
  return [
    ...common,
    policy.workloadId,
    String(policy.expectedSubject),
    policy.e2eeAlgorithm,
    policy.e2eeKeyId,
    policy.receiptAlgorithm,
    policy.receiptKeyId,
    policy.sourceRepository,
    policy.sourceCommit,
    policy.appId,
    policy.composeHash,
    policy.kmsRootPublicKey,
    policy.requiredUpstreamProviderType,
    ...policy.measurementProfiles.map(canonicalPhalaMeasurements),
  ].join('\n')
}

export const NVIDIA_ISSUER = 'https://nras.attestation.nvidia.com'
export const NVIDIA_JWKS = `${NVIDIA_ISSUER}/.well-known/jwks.json`
