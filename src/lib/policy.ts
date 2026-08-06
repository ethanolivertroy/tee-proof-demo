export type ProviderId = 'near-ai'

export interface WorkloadMeasurements {
  mrtd: string
  rtmr0: string
  rtmr1: string
  rtmr2: string
  rtmr3: string
  composeHash: string
  osImageHash: string
}

export interface NearModelPolicy {
  id: 'qwen35-122b'
  label: string
  model: string
  endpointLabel: string
  provider: ProviderId
  protocol: 'near-e2ee-v2'
  capturedAt: string
  gpuArchitecture: 'HOPPER'
  gpuCount: number
  measurementProfiles: readonly WorkloadMeasurements[]
}

const QWEN_122B_PROFILE: WorkloadMeasurements = {
  mrtd: 'b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217',
  rtmr0: 'bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590',
  rtmr1: 'c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc',
  rtmr2: '564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135',
  rtmr3: '18c28d262ab4733031c19fa1af233686e227a789955ba9dba2065b398c9f5dbfb76133d751dac412540dc5ac992b1b73',
  composeHash: '66007399f064f058af68771c552bcae150c9f88622305631b5141da1aa2f7b7e',
  osImageHash: '9b69bb1698bacbb6985409a2c272bcb892e09cdcea63d5399c6768b67d3ff677',
}

export const POLICY = {
  id: 'qwen35-122b',
  label: 'Qwen 3.5 122B',
  model: 'Qwen/Qwen3.5-122B-A10B',
  endpointLabel: 'qwen35-122b.completions.near.ai',
  provider: 'near-ai',
  protocol: 'near-e2ee-v2',
  capturedAt: '2026-08-02',
  gpuArchitecture: 'HOPPER',
  gpuCount: 8,
  measurementProfiles: [QWEN_122B_PROFILE],
} as const satisfies NearModelPolicy

function canonicalMeasurements(measurements: WorkloadMeasurements): string {
  return [
    measurements.mrtd,
    measurements.rtmr0,
    measurements.rtmr1,
    measurements.rtmr2,
    measurements.rtmr3,
    measurements.composeHash,
    measurements.osImageHash,
  ].join('\n')
}

export function canonicalPolicyText(policy: NearModelPolicy = POLICY): string {
  return [
    'tee-proof-demo-policy-v1',
    policy.id,
    policy.provider,
    policy.protocol,
    policy.model,
    policy.endpointLabel,
    policy.gpuArchitecture,
    String(policy.gpuCount),
    ...policy.measurementProfiles.map(canonicalMeasurements),
  ].join('\n')
}

export const NVIDIA_ISSUER = 'https://nras.attestation.nvidia.com'
export const NVIDIA_JWKS = `${NVIDIA_ISSUER}/.well-known/jwks.json`
