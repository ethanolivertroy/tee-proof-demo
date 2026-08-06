import { randomBytes } from '@noble/ciphers/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { verifyAttestation } from './attestation'
import { NEAR_ATTESTATION_ALLOWED_FIELDS, NEAR_ATTESTATION_REQUIRED_FIELDS } from './attestation-schema'
import { decryptFromModel, encryptForModel, generateClientKeys, sha256Hex, verifyEd25519Signature } from './crypto'
import { bytesToHex, textEncoder } from './encoding'
import { canonicalPolicyText, POLICY } from './policy'
import type { AttestationReport, CompletionResponse, SignatureReport, TrustEvidence, VerifiedCompletion } from './types'

export type TrustStage = 'fetching' | 'cpu' | 'gpu' | 'ready'
export const EVIDENCE_TTL_MS = 5 * 60 * 1000
const RECEIPT_ATTEMPTS = 6
const MAX_JSON_RESPONSE_CHARS = 2_000_000
const sleep = (milliseconds: number) => new Promise((resolve) => window.setTimeout(resolve, milliseconds))

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message)
}

function assertPlainObject(value: unknown, message: string): asserts value is Record<string, unknown> {
  assert(value != null && typeof value === 'object' && !Array.isArray(value), message)
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    assert(!Object.prototype.hasOwnProperty.call(value, key), `Unsafe response key: ${key}`)
  }
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const permitted = new Set(allowed)
  for (const key of Object.keys(value)) assert(permitted.has(key), `Unexpected ${label} field: ${key}`)
}

export function capEvidenceExpiry(providerExpiresAt: string, now = Date.now()): string {
  const providerExpiry = Date.parse(providerExpiresAt)
  assert(Number.isFinite(providerExpiry), 'Invalid evidence expiry')
  assert(providerExpiry > now, 'Trust evidence is already expired')
  return new Date(Math.min(providerExpiry, now + EVIDENCE_TTL_MS)).toISOString()
}

export function parseCompletionResponse(value: unknown): CompletionResponse {
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
  assert(value.model === POLICY.model, 'Completion model does not match the approved policy')
  assert(Array.isArray(value.choices) && value.choices.length > 0, 'Completion choices are missing')
  return value as unknown as CompletionResponse
}

export function parseAttestationResponse(value: unknown): AttestationReport {
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

async function fetchJson(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(path, init)
  const text = await response.text()
  if (text.length > MAX_JSON_RESPONSE_CHARS) throw new Error('Provider response exceeded the client limit')
  if (!response.ok) throw new Error(`Request failed (${response.status}): ${text.slice(0, 180)}`)
  return JSON.parse(text)
}

export async function establishTrust(onStage?: (stage: TrustStage) => void): Promise<TrustEvidence> {
  const nonce = bytesToHex(randomBytes(32))
  onStage?.('fetching')
  const report = parseAttestationResponse(await fetchJson(`/api/attestation?nonce=${encodeURIComponent(nonce)}`, { cache: 'no-store' }))
  assert(report.model_name === POLICY.model, `Attestation model mismatch: ${report.model_name}`)
  assert(report.signing_algo === 'ed25519', `Unsupported completion signature algorithm: ${report.signing_algo}`)
  assert(/^[0-9a-f]{64}$/i.test(report.signing_public_key), 'Invalid Ed25519 completion key')
  const { cpu, gpu } = await verifyAttestation(report, nonce, POLICY, onStage)
  const evidence: TrustEvidence = {
    modelId: POLICY.id,
    provider: 'near-ai',
    protocol: 'near-e2ee-v2',
    verifiedAt: new Date().toISOString(),
    expiresAt: capEvidenceExpiry(gpu.expiresAt),
    nonce,
    model: report.model_name,
    endpointLabel: POLICY.endpointLabel,
    signingPublicKey: report.signing_public_key.toLowerCase(),
    policyDigest: bytesToHex(sha256(textEncoder.encode(canonicalPolicyText()))),
    composeHash: report.info.tcb_info.compose_hash,
    osImageHash: report.info.tcb_info.os_image_hash,
    cpu,
    gpu,
    raw: report,
  }
  onStage?.('ready')
  return evidence
}

export function evidenceIsFresh(evidence: TrustEvidence, now = Date.now()): boolean {
  return Date.parse(evidence.expiresAt) > now
}

export function assertEvidenceFresh(evidence: TrustEvidence): void {
  assert(evidenceIsFresh(evidence), 'Trust evidence expired. Verify again before sending.')
  assert(evidence.modelId === POLICY.id && evidence.model === POLICY.model, 'Attestation belongs to a different model')
  assert(evidence.endpointLabel === POLICY.endpointLabel, 'Endpoint changed after verification')
  assert(evidence.provider === POLICY.provider && evidence.protocol === POLICY.protocol, 'Provider protocol changed after verification')
  const expectedPolicyDigest = bytesToHex(sha256(textEncoder.encode(canonicalPolicyText())))
  assert(evidence.policyDigest === expectedPolicyDigest, 'Local verification policy changed after verification')
}

async function fetchSignature(chatId: string): Promise<SignatureReport> {
  let lastStatus = 0
  for (let attempt = 0; attempt < RECEIPT_ATTEMPTS; attempt += 1) {
    const response = await fetch(`/api/signature/${encodeURIComponent(chatId)}`, { cache: 'no-store' })
    if (response.ok) return response.json() as Promise<SignatureReport>
    lastStatus = response.status
    if (response.status !== 404) throw new Error(`Completion signature unavailable (${response.status})`)
    await sleep(150 * 2 ** attempt)
  }
  throw new Error(`Completion signature was not found after retries (${lastStatus})`)
}

export function verifyCompletionSignature(
  signature: SignatureReport,
  evidence: TrustEvidence,
  requestText: string,
  responseText: string,
) {
  assert(signature.signing_algo.toLowerCase() === 'ed25519', 'Unexpected completion signature algorithm')
  assert(signature.signing_address.toLowerCase() === evidence.signingPublicKey, 'Completion signer is not the attested model key')
  const requestHash = sha256Hex(requestText)
  const responseHash = sha256Hex(responseText)
  const expectedText = `${POLICY.model}:${requestHash}:${responseHash}`
  assert(signature.text === expectedText, 'Signed completion payload does not match the exact request and response')
  assert(verifyEd25519Signature(signature.signature, signature.text, evidence.signingPublicKey), 'Completion signature verification failed')
  return {
    provider: 'near-ai' as const,
    model: POLICY.model,
    requestHash,
    responseHash,
    signer: signature.signing_address.toLowerCase(),
    signature: signature.signature.toLowerCase(),
    signedText: signature.text,
    verifiedAt: new Date().toISOString(),
  }
}

export async function sendEncryptedPrompt(prompt: string, evidence: TrustEvidence): Promise<VerifiedCompletion> {
  assertEvidenceFresh(evidence)
  const cleanPrompt = prompt.trim()
  assert(cleanPrompt.length > 0 && cleanPrompt.length <= 2_000, 'Prompt must contain 1 to 2,000 characters')
  const client = generateClientKeys()
  const requestBody = {
    model: POLICY.model,
    messages: [{ role: 'user', content: encryptForModel(cleanPrompt, evidence.signingPublicKey) }],
    max_tokens: 256,
    stream: false,
  }
  const requestText = JSON.stringify(requestBody)
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-client-pub-key': bytesToHex(client.ed25519PublicKey),
      'x-encryption-version': '2',
      'x-model-pub-key': evidence.signingPublicKey,
      'x-signing-algo': 'ed25519',
    },
    body: requestText,
  })
  const responseText = await response.text()
  if (!response.ok) throw new Error(`Encrypted completion failed (${response.status}): ${responseText.slice(0, 160)}`)
  const body = parseCompletionResponse(JSON.parse(responseText))
  const signature = await fetchSignature(body.id)
  const receipt = verifyCompletionSignature(signature, evidence, requestText, responseText)
  const encryptedAnswer = body.choices[0]?.message?.content ?? body.choices[0]?.message?.reasoning_content
  assert(encryptedAnswer, 'Completion response contained no encrypted text')
  return { content: decryptFromModel(encryptedAnswer, client.x25519SecretKey), receipt }
}
