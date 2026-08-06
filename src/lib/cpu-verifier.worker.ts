/// <reference lib="webworker" />

import { verifyCpuAttestation } from './cpu-verifier-core'
import type { NearModelPolicy } from './policy'
import type { AttestationReport, CpuEvidence } from './types'

interface CpuWorkerRequest {
  report: AttestationReport
  requestedNonce: string
  policy: NearModelPolicy
}

interface CpuWorkerReply {
  ok: boolean
  evidence?: CpuEvidence
  error?: string
}

self.onmessage = async (event: MessageEvent<CpuWorkerRequest>) => {
  let reply: CpuWorkerReply
  try {
    reply = {
      ok: true,
      evidence: await verifyCpuAttestation(event.data.report, event.data.requestedNonce, event.data.policy),
    }
  } catch (error) {
    reply = { ok: false, error: error instanceof Error ? error.message : 'Intel quote verification failed' }
  }
  self.postMessage(reply)
}
