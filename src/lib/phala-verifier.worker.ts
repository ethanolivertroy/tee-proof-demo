/// <reference lib="webworker" />

import type { AttestationReport } from './phala-aci'
import { verifyPhalaGateway } from './phala-verifier-core'
import type { PhalaModelPolicy } from './policy'
import { wireVerifierWorker } from './verifier-worker'

interface PhalaWorkerRequest {
  report: AttestationReport
  requestedNonce: string
  policy: PhalaModelPolicy
}

wireVerifierWorker(
  (request: PhalaWorkerRequest) => verifyPhalaGateway(request.report, request.requestedNonce, request.policy),
  'Phala ACI verification failed',
)
