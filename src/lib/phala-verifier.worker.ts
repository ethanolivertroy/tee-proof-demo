/// <reference lib="webworker" />

import { verifyPhalaGateway } from './phala-verifier-core'
import type { AttestationReport } from './phala-aci'
import type { PhalaModelPolicy } from './policy'
import type { PhalaGatewayEvidence } from './types'

interface Request {
  report: AttestationReport
  requestedNonce: string
  policy: PhalaModelPolicy
}

interface Reply {
  ok: boolean
  evidence?: PhalaGatewayEvidence
  expiresAt?: string
  error?: string
}

self.onmessage = async (event: MessageEvent<Request>) => {
  let reply: Reply
  try {
    const verified = await verifyPhalaGateway(event.data.report, event.data.requestedNonce, event.data.policy)
    reply = { ok: true, ...verified }
  } catch (error) {
    reply = { ok: false, error: error instanceof Error ? error.message : 'Phala ACI verification failed' }
  }
  self.postMessage(reply)
}
