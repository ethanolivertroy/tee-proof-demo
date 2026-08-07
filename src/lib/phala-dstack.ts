import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256, sha384 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, concatBytes, equalBytes, hexToBytes, textEncoder } from './encoding'
import { assert, isRecord } from './guards'
import type { PhalaModelPolicy } from './policy'

const RUNTIME_EVENT_TYPE = 0x08000001

interface DstackEvent {
  imr: number
  event_type: number
  digest: string
  event: string
  event_payload: string
}

interface CustodyKey {
  role?: unknown
  purpose?: unknown
  public_key?: unknown
  signature_chain?: unknown
}

interface DstackEvidence {
  event_log: string
  app_compose: string
  key_custody: {
    provider: string
    keys: CustodyKey[]
  }
}

function asEvent(value: unknown): DstackEvent {
  assert(isRecord(value), 'Invalid dstack event')
  assert(Number.isInteger(value.imr) && Number.isInteger(value.event_type), 'Invalid dstack event registers')
  assert(typeof value.digest === 'string' && typeof value.event === 'string' && typeof value.event_payload === 'string', 'Invalid dstack event fields')
  return value as unknown as DstackEvent
}

function runtimeDigest(event: DstackEvent): Uint8Array {
  if (event.event_type !== RUNTIME_EVENT_TYPE) return hexToBytes(event.digest)
  const eventType = new Uint8Array(4)
  new DataView(eventType.buffer).setUint32(0, event.event_type, true)
  const payload = event.event_payload.length === 0 ? new Uint8Array() : hexToBytes(event.event_payload)
  return sha384(concatBytes(eventType, textEncoder.encode(':'), textEncoder.encode(event.event), textEncoder.encode(':'), payload))
}

function replayRtmr(events: readonly DstackEvent[], imr: number): Uint8Array {
  let current = new Uint8Array(48)
  for (const event of events) {
    if (event.imr !== imr) continue
    const digest = runtimeDigest(event)
    const padded = digest.length < 48 ? concatBytes(digest, new Uint8Array(48 - digest.length)) : digest
    current = sha384(concatBytes(current, padded))
  }
  return current
}

function oneBeforeSystemReady(events: readonly DstackEvent[], name: string): DstackEvent {
  const matches: DstackEvent[] = []
  for (const event of events) {
    if (event.imr === 3 && event.event_type === RUNTIME_EVENT_TYPE && event.event === 'system-ready') break
    if (event.imr === 3 && event.event_type === RUNTIME_EVENT_TYPE && event.event === name) matches.push(event)
  }
  assert(matches.length === 1, `Expected one measured ${name} event before system-ready`)
  return matches[0]!
}

function recoverKmsPublicKey(message: Uint8Array, signatureHex: string): Uint8Array {
  const signature = hexToBytes(signatureHex)
  assert(signature.length === 65, `KMS signature must be 65 bytes, got ${signature.length}`)
  let recovery = signature[64]!
  if (recovery >= 27 && recovery <= 30) recovery -= 27
  assert(recovery <= 3, 'Invalid KMS recovery id')
  return secp256k1.Signature
    .fromBytes(signature.slice(0, 64), 'compact')
    .addRecoveryBit(recovery)
    .recoverPublicKey(keccak_256(message))
    .toBytes(true)
}

export interface VerifiedDstackEvidence {
  appId: string
  composeHash: string
  kmsRootPublicKey: string
  sourceRepository: string
  sourceCommit: string
}

export function verifyMeasuredSourceProvenance(appCompose: string, policy: PhalaModelPolicy): {
  sourceRepository: string
  sourceCommit: string
} {
  let descriptor: unknown
  try {
    descriptor = JSON.parse(appCompose)
  } catch {
    throw new Error('Measured app Compose descriptor is not valid JSON')
  }
  assert(isRecord(descriptor), 'Measured app Compose descriptor is invalid')
  const composeFile = descriptor.docker_compose_file
  assert(typeof composeFile === 'string', 'Measured Docker Compose file is missing')

  const environmentValue = (name: string): string => {
    const prefix = `- ${name}=`
    const matches = composeFile
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line.startsWith(prefix))
      .map((line) => line.slice(prefix.length))
    assert(matches.length === 1, `Measured Docker Compose must contain exactly one ${name}`)
    return matches[0]!
  }

  const sourceRepository = environmentValue('PRIVATE_AI_GATEWAY_REPO_URL')
  const sourceCommit = environmentValue('PRIVATE_AI_GATEWAY_REPO_COMMIT')
  const expectedRepository = policy.sourceRepository.replace(/\.git$/u, '')
  assert(sourceRepository.replace(/\.git$/u, '') === expectedRepository, 'Measured source repository is not approved')
  assert(sourceCommit === policy.sourceCommit, 'Measured source commit is not approved')
  return { sourceRepository, sourceCommit }
}

export function verifyDstackEvidence(
  evidenceValue: unknown,
  identityPublicKeyHex: string,
  quoteRtmr3: Uint8Array,
  policy: PhalaModelPolicy,
): VerifiedDstackEvidence {
  assert(isRecord(evidenceValue), 'Missing dstack evidence')
  const evidence = evidenceValue as Partial<DstackEvidence>
  assert(typeof evidence.event_log === 'string', 'Missing dstack event log')
  assert(typeof evidence.app_compose === 'string', 'Missing measured app Compose')

  const parsed = JSON.parse(evidence.event_log) as unknown
  assert(Array.isArray(parsed), 'Dstack event log is not an array')
  const events = parsed.map(asEvent)
  assert(equalBytes(replayRtmr(events, 3), quoteRtmr3), 'Dstack event log does not replay to quote RTMR3')

  const appId = bytesToHex(hexToBytes(oneBeforeSystemReady(events, 'app-id').event_payload))
  const composeHash = bytesToHex(hexToBytes(oneBeforeSystemReady(events, 'compose-hash').event_payload))
  assert(appId === policy.appId, `Dstack app id is not approved: ${appId}`)
  assert(composeHash === policy.composeHash, `Dstack Compose hash is not approved: ${composeHash}`)
  assert(bytesToHex(sha256(textEncoder.encode(evidence.app_compose))) === composeHash, 'Dstack Compose preimage is not bound to the measured hash')
  const source = verifyMeasuredSourceProvenance(evidence.app_compose, policy)

  const custody = evidence.key_custody
  assert(custody && custody.provider === 'dstack-kms' && Array.isArray(custody.keys), 'Missing dstack KMS custody evidence')
  const identity = custody.keys.find((entry) => entry.role === 'identity')
  assert(identity && typeof identity.public_key === 'string', 'Missing identity-key custody evidence')
  assert(identity.public_key.toLowerCase() === identityPublicKeyHex.toLowerCase(), 'Identity custody key does not match workload identity')
  assert(typeof identity.purpose === 'string', 'Identity custody purpose is missing')
  assert(Array.isArray(identity.signature_chain) && identity.signature_chain.length === 2 && identity.signature_chain.every((value) => typeof value === 'string'), 'Invalid identity custody signature chain')

  const identityPublicKey = secp256k1.Point.fromBytes(hexToBytes(identityPublicKeyHex)).toBytes(true)
  const purposeMessage = textEncoder.encode(`${identity.purpose}:${bytesToHex(identityPublicKey)}`)
  const appPublicKey = recoverKmsPublicKey(purposeMessage, identity.signature_chain[0] as string)
  const rootMessage = concatBytes(textEncoder.encode('dstack-kms-issued:'), hexToBytes(appId), appPublicKey)
  const kmsRootPublicKey = bytesToHex(recoverKmsPublicKey(rootMessage, identity.signature_chain[1] as string))
  assert(kmsRootPublicKey === policy.kmsRootPublicKey, `Dstack KMS root is not approved: ${kmsRootPublicKey}`)

  return { appId, composeHash, kmsRootPublicKey, ...source }
}
