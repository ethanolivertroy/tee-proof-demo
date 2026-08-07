import { randomBytes } from '@noble/ciphers/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { verifyAttestation } from './attestation'
import { NEAR_ATTESTATION_ALLOWED_FIELDS, NEAR_ATTESTATION_REQUIRED_FIELDS } from './attestation-schema'
import { decryptFromModel, encryptForModel, generateClientKeys, sha256Hex, verifyEd25519Signature } from './crypto'
import { bytesToHex, textEncoder } from './encoding'
import { assert, assertPlainObject } from './guards'
import { accessHeaders, fetchJson } from './http'
import { openE2eeChannel, verifyReportBinding, type AttestationReport as AciAttestationReport } from './phala-aci'
import { verifyPhalaCompletionReceipt } from './phala-completion'
import { canonicalPolicyText, getModelPolicy, isNearPolicy, type ModelId, type ModelPolicy, type NearModelPolicy, type PhalaModelPolicy } from './policy'
import type { AttestationReport, CompletionResponse, NearTrustEvidence, PhalaGatewayEvidence, PhalaTrustEvidence, SignatureReport, TrustEvidence, VerifiedCompletion } from './types'

export type TrustStage = 'fetching' | 'cpu' | 'gpu' | 'ready'
export const EVIDENCE_TTL_MS = 5 * 60 * 1000
const RECEIPT_TIMEOUT_MS = 12_000
const sleep = (milliseconds: number) => new Promise((resolve) => window.setTimeout(resolve, milliseconds))

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const permitted = new Set(allowed)
  for (const key of Object.keys(value)) assert(permitted.has(key), `Unexpected ${label} field: ${key}`)
}

export async function verifyDemoAccess(accessToken: string): Promise<void> {
  assert(accessToken.length >= 20 && accessToken.length <= 256, 'Access token must contain 20 to 256 characters')
  const response = await fetch('/api/access', { method: 'POST', headers: accessHeaders(accessToken), cache: 'no-store' })
  if (!response.ok) throw new Error(response.status === 401 ? 'Access token was rejected' : `Access gate unavailable (${response.status})`)
}

export function capEvidenceExpiry(providerExpiresAt: string, now = Date.now()): string {
  const providerExpiry = Date.parse(providerExpiresAt)
  assert(Number.isFinite(providerExpiry), 'Invalid evidence expiry')
  assert(providerExpiry > now, 'Trust evidence is already expired')
  return new Date(Math.min(providerExpiry, now + EVIDENCE_TTL_MS)).toISOString()
}

export function parseCompletionResponse(value: unknown, policy: ModelPolicy): CompletionResponse {
  assertPlainObject(value, 'Invalid completion response')
  exactKeys(value, [
    'id', 'object', 'created', 'model', 'choices', 'usage', 'service_tier', 'system_fingerprint', 'metadata',
    'prompt_logprobs', 'prompt_token_ids', 'prompt_text', 'kv_transfer_params', 'ec_transfer_params', 'metrics',
  ], 'completion')
  if (value.metadata !== undefined) {
    assertPlainObject(value.metadata, 'Invalid completion metadata')
    exactKeys(value.metadata, ['weight_version'], 'completion metadata')
    assert(typeof value.metadata.weight_version === 'string', 'Invalid completion weight version metadata')
  }
  for (const key of ['prompt_logprobs', 'prompt_token_ids', 'prompt_text', 'kv_transfer_params', 'ec_transfer_params', 'metrics']) {
    assert(value[key] === undefined || value[key] === null, `Unexpected non-null completion metadata: ${key}`)
  }
  assert(typeof value.id === 'string' && value.id.length > 0, 'Completion id is missing')
  assert(value.model === policy.model, 'Completion model does not match the selected policy')
  assert(Array.isArray(value.choices) && value.choices.length > 0, 'Completion choices are missing')
  return value as unknown as CompletionResponse
}

export function parseNearAttestationResponse(value: unknown): AttestationReport {
  assertPlainObject(value, 'Invalid attestation response')
  exactKeys(value, NEAR_ATTESTATION_ALLOWED_FIELDS, 'attestation')
  for (const field of NEAR_ATTESTATION_REQUIRED_FIELDS) {
    assert(Object.prototype.hasOwnProperty.call(value, field), `Missing attestation field: ${field}`)
  }
  assertPlainObject(value.info, 'Invalid attestation info')
  if (value.event_log !== undefined) assert(Array.isArray(value.event_log), 'Invalid attestation event log')
  if (value.all_attestations !== undefined) assert(Array.isArray(value.all_attestations), 'Invalid attestation list')
  if (value.compose_manager_attestation !== undefined) assertPlainObject(value.compose_manager_attestation, 'Invalid compose manager attestation')
  if (value.ohttp_key_config !== undefined) assert(typeof value.ohttp_key_config === 'string', 'Invalid OHTTP key configuration')
  if (value.ohttp_attestation !== undefined) assertPlainObject(value.ohttp_attestation, 'Invalid OHTTP attestation')
  return value as unknown as AttestationReport
}

function verifyPhalaInWorker(report: AciAttestationReport, requestedNonce: string, policy: PhalaModelPolicy): Promise<{ evidence: PhalaGatewayEvidence; expiresAt: string }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./phala-verifier.worker.ts', import.meta.url), { type: 'module' })
    const timer = window.setTimeout(() => {
      worker.terminate()
      reject(new Error('Phala ACI verifier timed out'))
    }, 90_000)
    worker.onmessage = (event: MessageEvent<{ ok: boolean; evidence?: PhalaGatewayEvidence; expiresAt?: string; error?: string }>) => {
      window.clearTimeout(timer)
      worker.terminate()
      if (!event.data.ok || !event.data.evidence || !event.data.expiresAt) reject(new Error(event.data.error ?? 'Phala ACI verification failed'))
      else resolve({ evidence: event.data.evidence, expiresAt: event.data.expiresAt })
    }
    worker.onerror = () => {
      window.clearTimeout(timer)
      worker.terminate()
      reject(new Error('Phala ACI verifier worker failed'))
    }
    worker.postMessage({ report, requestedNonce, policy })
  })
}

async function establishNearTrust(policy: NearModelPolicy, onStage?: (stage: 'fetching' | 'cpu' | 'gpu') => void): Promise<NearTrustEvidence> {
  const nonce = bytesToHex(randomBytes(32))
  onStage?.('fetching')
  const report = parseNearAttestationResponse(await fetchJson(`/api/attestation?model=${encodeURIComponent(policy.id)}&nonce=${encodeURIComponent(nonce)}`, { cache: 'no-store' }))
  assert(report.model_name === policy.model, `Attestation model mismatch: ${report.model_name}`)
  assert(report.signing_algo === 'ed25519', `Unsupported completion signature algorithm: ${report.signing_algo}`)
  assert(/^[0-9a-f]{64}$/i.test(report.signing_public_key), 'Invalid Ed25519 completion key')
  const { cpu, gpu } = await verifyAttestation(report, nonce, policy, onStage)
  return {
    modelId: policy.id,
    provider: 'near-ai',
    protocol: 'near-e2ee-v2',
    verifiedAt: new Date().toISOString(),
    expiresAt: capEvidenceExpiry(gpu.expiresAt),
    nonce,
    model: report.model_name,
    endpointLabel: policy.endpointLabel,
    signingPublicKey: report.signing_public_key.toLowerCase(),
    policyDigest: bytesToHex(sha256(textEncoder.encode(canonicalPolicyText(policy)))),
    composeHash: report.info.tcb_info.compose_hash,
    osImageHash: report.info.tcb_info.os_image_hash,
    cpu,
    gpu,
    raw: report,
  }
}

async function establishPhalaTrust(policy: PhalaModelPolicy, onStage?: (stage: 'fetching' | 'cpu' | 'gpu') => void): Promise<PhalaTrustEvidence> {
  const nonce = bytesToHex(randomBytes(32))
  onStage?.('fetching')
  const value = await fetchJson(`/api/attestation?model=${encodeURIComponent(policy.id)}&nonce=${encodeURIComponent(nonce)}`, { cache: 'no-store' })
  assertPlainObject(value, 'Invalid Phala ACI attestation response')
  onStage?.('cpu')
  const report = value as unknown as AciAttestationReport
  const verified = await verifyPhalaInWorker(report, nonce, policy)
  onStage?.('gpu')
  return {
    modelId: policy.id,
    provider: 'phala-cloud',
    protocol: 'phala-aci-v2',
    verifiedAt: new Date().toISOString(),
    expiresAt: capEvidenceExpiry(verified.expiresAt),
    nonce,
    model: policy.model,
    endpointLabel: policy.endpointLabel,
    signingPublicKey: verified.evidence.receiptPublicKey,
    policyDigest: bytesToHex(sha256(textEncoder.encode(canonicalPolicyText(policy)))),
    gateway: verified.evidence,
    raw: report,
  }
}

export async function establishTrust(modelId: ModelId, onStage?: (stage: TrustStage) => void): Promise<TrustEvidence> {
  const policy = getModelPolicy(modelId)
  const evidence = isNearPolicy(policy)
    ? await establishNearTrust(policy, onStage)
    : await establishPhalaTrust(policy, onStage)
  onStage?.('ready')
  return evidence
}

export function evidenceIsFresh(evidence: TrustEvidence, now = Date.now()): boolean {
  return Date.parse(evidence.expiresAt) > now
}

export function assertEvidenceFresh(evidence: TrustEvidence): void {
  assert(evidenceIsFresh(evidence), 'Trust evidence expired. Verify again before sending.')
  const policy = getModelPolicy(evidence.modelId)
  assert(evidence.model === policy.model, 'Selected model changed after verification')
  assert(evidence.endpointLabel === policy.endpointLabel, 'Endpoint changed after verification')
  assert(evidence.provider === policy.provider && evidence.protocol === policy.protocol, 'Provider protocol changed after verification')
  assert(evidence.policyDigest === bytesToHex(sha256(textEncoder.encode(canonicalPolicyText(policy)))), 'Local verification policy changed after verification')
}

function completionText(response: CompletionResponse): string {
  const message = response.choices[0]?.message
  assert(!message || !Object.hasOwn(message, 'reasoning'), 'Completion included an unsupported unencrypted reasoning field')
  const content = message?.content || message?.reasoning_content
  assert(typeof content === 'string' && content.length > 0, 'Completion contained no text')
  return content
}

async function fetchNearSignature(chatId: string, modelId: string, accessToken: string): Promise<SignatureReport> {
  const query = new URLSearchParams({ model: modelId })
  let lastStatus = 0
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const response = await fetch(`/api/signature/${encodeURIComponent(chatId)}?${query}`, { cache: 'no-store', headers: accessHeaders(accessToken) })
    if (response.ok) return response.json() as Promise<SignatureReport>
    lastStatus = response.status
    if (response.status !== 404) throw new Error(`Completion signature unavailable (${response.status})`)
    await sleep(150 * 2 ** attempt)
  }
  throw new Error(`Completion signature was not found after retries (${lastStatus})`)
}

export function verifyCompletionSignature(signature: SignatureReport, evidence: TrustEvidence, policy: NearModelPolicy, requestText: string, responseText: string) {
  assert(evidence.protocol === 'near-e2ee-v2', 'NEAR receipt verification requires NEAR trust evidence')
  assert(signature.signing_algo.toLowerCase() === 'ed25519', 'Unexpected completion signature algorithm')
  assert(signature.signing_address.toLowerCase() === evidence.signingPublicKey, 'Completion signer is not the attested model key')
  const requestHash = sha256Hex(requestText)
  const responseHash = sha256Hex(responseText)
  const expectedText = `${policy.model}:${requestHash}:${responseHash}`
  assert(signature.text === expectedText, 'Signed completion payload does not match the exact request and response')
  assert(verifyEd25519Signature(signature.signature, signature.text, evidence.signingPublicKey), 'Completion signature verification failed')
  return {
    provider: 'near-ai' as const,
    model: policy.model,
    requestHash,
    responseHash,
    signer: signature.signing_address.toLowerCase(),
    signature: signature.signature.toLowerCase(),
    signedText: signature.text,
    verifiedAt: new Date().toISOString(),
  }
}

async function sendNearPrompt(prompt: string, evidence: NearTrustEvidence, policy: NearModelPolicy, accessToken: string): Promise<VerifiedCompletion> {
  const client = generateClientKeys()
  const requestBody = {
    model: policy.model,
    messages: [{ role: 'user', content: encryptForModel(prompt, evidence.signingPublicKey) }],
    max_tokens: 256,
    stream: false,
  }
  const requestText = JSON.stringify(requestBody)
  const response = await fetch(`/api/chat?model=${encodeURIComponent(policy.id)}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...accessHeaders(accessToken),
      'x-client-pub-key': bytesToHex(client.ed25519PublicKey),
      'x-encryption-version': '2',
      'x-model-pub-key': evidence.signingPublicKey,
      'x-signing-algo': 'ed25519',
    },
    body: requestText,
  })
  const responseText = await response.text()
  if (!response.ok) throw new Error(`Encrypted completion failed (${response.status}): ${responseText.slice(0, 160)}`)
  const body = parseCompletionResponse(JSON.parse(responseText), policy)
  const signature = await fetchNearSignature(body.id, policy.id, accessToken)
  const receipt = verifyCompletionSignature(signature, evidence, policy, requestText, responseText)
  const encryptedAnswer = body.choices[0]?.message?.content ?? body.choices[0]?.message?.reasoning_content
  assert(encryptedAnswer, 'Completion response contained no encrypted text')
  return { content: decryptFromModel(encryptedAnswer, client.x25519SecretKey), receipt }
}

async function sendPhalaPrompt(prompt: string, evidence: PhalaTrustEvidence, policy: PhalaModelPolicy, accessToken: string): Promise<VerifiedCompletion> {
  const binding = await verifyReportBinding(evidence.raw, evidence.nonce, { trustPlatformClock: true })
  assert(binding.ok && binding.workloadKeysetDigest === evidence.gateway.workloadKeysetDigest, 'Phala keyset no longer matches verified trust evidence')
  const channel = await openE2eeChannel(evidence.raw, binding, {
    keyId: evidence.gateway.e2eeKeyId,
    algorithm: evidence.gateway.e2eeAlgorithm,
    publicKey: evidence.gateway.e2eePublicKey,
  })
  const plaintext = {
    model: policy.model,
    messages: [{ role: 'user', content: prompt }],
    stream: false,
    max_tokens: 512,
    provider: { aci_verified: true },
  }
  const sealed = await channel.seal(plaintext)
  const response = await fetch(`/api/chat?model=${encodeURIComponent(policy.id)}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...accessHeaders(accessToken), ...sealed.headers },
    body: JSON.stringify(sealed.body),
  })
  const responseWireBody = await response.text()
  if (!response.ok) throw new Error(`Phala completion failed (${response.status}): ${responseWireBody.slice(0, 180)}`)
  assert(response.headers.get('x-e2ee-applied') === 'true', 'Phala did not confirm E2EE response encryption')
  assert(response.headers.get('x-e2ee-version') === '2', 'Phala E2EE response version mismatch')
  const receiptId = response.headers.get('x-receipt-id')
  assert(receiptId, 'Phala completion omitted its receipt id')
  const opened = await channel.open(JSON.parse(responseWireBody) as Record<string, unknown>)
  const body = parseCompletionResponse(opened, policy)
  const receipt = await Promise.race([
    verifyPhalaCompletionReceipt({
      receiptId,
      policy,
      keyset: evidence.raw.attestation.workload_keyset,
      plaintextRequestBody: JSON.stringify(plaintext),
      responseWireBody,
      responseCleartextBody: JSON.stringify(opened),
      accessToken,
    }),
    new Promise<never>((_, reject) => window.setTimeout(() => reject(new Error('Phala receipt verification timed out')), RECEIPT_TIMEOUT_MS)),
  ])
  return { content: completionText(body), receipt: receipt.receipt }
}

export async function sendEncryptedPrompt(prompt: string, evidence: TrustEvidence, accessToken: string): Promise<VerifiedCompletion> {
  assertEvidenceFresh(evidence)
  const cleanPrompt = prompt.trim()
  assert(cleanPrompt.length > 0 && cleanPrompt.length <= 2_000, 'Prompt must contain 1 to 2,000 characters')
  assert(accessToken.length >= 20, 'Access token is required')
  const policy = getModelPolicy(evidence.modelId)
  if (isNearPolicy(policy)) {
    assert(evidence.protocol === 'near-e2ee-v2', 'NEAR route requires NEAR trust evidence')
    return sendNearPrompt(cleanPrompt, evidence, policy, accessToken)
  }
  assert(evidence.protocol === 'phala-aci-v2', 'Phala route requires Phala ACI trust evidence')
  return sendPhalaPrompt(cleanPrompt, evidence, policy, accessToken)
}
