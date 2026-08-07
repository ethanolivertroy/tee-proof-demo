/// <reference lib="webworker" />

import { verifyCpuAttestation } from './cpu-verifier-core'
import type { NearModelPolicy } from './policy'
import type { AttestationReport } from './types'
import { wireVerifierWorker } from './verifier-worker'

interface CpuWorkerRequest {
  report: AttestationReport
  requestedNonce: string
  policy: NearModelPolicy
}

wireVerifierWorker(
  (request: CpuWorkerRequest) => verifyCpuAttestation(request.report, request.requestedNonce, request.policy),
  'Intel quote verification failed',
)
