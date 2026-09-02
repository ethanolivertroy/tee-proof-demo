/**
 * dstack evidence under the ACI `tdx` policy (spec/aci.md §4.2, cited from
 * ./phala-aci/index.ts): replay the boot event log to the quote's RTMR3, bind
 * the measured Compose to its hash and to the pinned source (§9.1 check 4),
 * and walk the dstack KMS custody chain for the keys the browser will use
 * (§3.3, §9.1 check 5). Mirrors src/aci/verifier/dstack.rs in the upstream
 * repository, extended to cover the E2EE key as well as the receipt key.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256, sha384 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { normalizeSecp256k1RecoveryId } from './crypto'
import { bytesToHex, concatBytes, equalBytes, hexToBytes, textEncoder } from './encoding'
import { assert, isRecord } from './guards'
import type { PhalaModelPolicy } from './policy'

const RUNTIME_EVENT_TYPE = 0x08000001

/** KMS derivation purposes per custody role; the chain must be for the role's path, not any KMS key the app holds. */
const CUSTODY_PURPOSES = {
  receipt: 'aci.receipt.ed25519.v1',
  'e2ee-x25519': 'aci.e2ee.x25519.v1',
} as const

export type CustodyRole = keyof typeof CUSTODY_PURPOSES

/** A keyset entry the gateway verifier approved and now needs custody evidence for. */
export interface ApprovedCustodyKey {
  role: CustodyRole
  algo: string
  publicKey: string
}

interface DstackEvent {
  imr: number
  event_type: number
  digest: string
  event: string
  event_payload: string
}

function asEvent(value: unknown): DstackEvent {
  assert(isRecord(value), 'Invalid dstack event')
  assert(Number.isInteger(value.imr) && Number.isInteger(value.event_type), 'Invalid dstack event registers')
  assert(typeof value.digest === 'string' && typeof value.event === 'string' && typeof value.event_payload === 'string', 'Invalid dstack event fields')
  return value as unknown as DstackEvent
}

// dstack runtime events are re-digested from their semantic fields so a log
// entry cannot borrow another event's digest.
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
  const recovery = normalizeSecp256k1RecoveryId(signature[64]!)
  assert(recovery !== null, 'Invalid KMS recovery id')
  return secp256k1.Signature
    .fromBytes(signature.slice(0, 64), 'compact')
    .addRecoveryBit(recovery)
    .recoverPublicKey(keccak_256(message))
    .toBytes(true)
}

function compressedSecp256k1(hex: string): Uint8Array {
  return secp256k1.Point.fromBytes(hexToBytes(hex)).toBytes(true)
}

export interface VerifiedDstackEvidence {
  appId: string
  composeHash: string
  kmsRootPublicKey: string
  sourceRepository: string
  sourceCommit: string
}

function stripGitSuffix(url: string): string {
  return url.replace(/\.git$/u, '')
}

/**
 * §9.1 check 4: the pinned source repository and commit must appear in the
 * measured Compose file (as the launcher's PRIVATE_AI_GATEWAY_REPO_* values),
 * which sha256-matches the compose-hash event replayed into RTMR3. The report's
 * unmeasured `source_provenance` is checked for consistency in
 * {@link verifyDstackEvidence}, never trusted on its own (§4.1).
 */
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
  assert(stripGitSuffix(sourceRepository) === stripGitSuffix(policy.sourceRepository), 'Measured source repository is not approved')
  assert(sourceCommit === policy.sourceCommit, 'Measured source commit is not approved')
  return { sourceRepository, sourceCommit }
}

/**
 * §3.3 custody for one approved key: the custody entry publishes the same key,
 * the KMS app key signed `<purpose>:<compressed kms_public_key>`, and the KMS
 * root signed `dstack-kms-issued:<app_id><compressed app key>`. Both signers
 * are recovered, so the root must equal the pinned one and the app key must
 * be the same across every role. The link from the signed secp256k1
 * `kms_public_key` to the published Ed25519 or X25519 key is enforced by the
 * measured workload code, which is why the source pin above is required.
 */
function verifyCustodyChain(entries: readonly unknown[], approved: ApprovedCustodyKey, appId: Uint8Array): { appPublicKey: Uint8Array; rootPublicKey: string } {
  const entry = entries.find((candidate) => isRecord(candidate) && candidate.role === approved.role)
  assert(isRecord(entry), `Missing ${approved.role} key custody evidence`)
  assert(typeof entry.public_key === 'string' && entry.public_key.toLowerCase() === approved.publicKey.toLowerCase(), `${approved.role} custody key does not match the attested keyset`)
  assert(entry.algo === approved.algo, `${approved.role} custody algorithm does not match the attested keyset`)
  assert(entry.purpose === CUSTODY_PURPOSES[approved.role], `${approved.role} custody purpose is not ${CUSTODY_PURPOSES[approved.role]}`)
  assert(typeof entry.kms_public_key === 'string', `${approved.role} custody is missing its KMS public key`)
  const chain = entry.signature_chain
  assert(Array.isArray(chain) && chain.length === 2 && chain.every((value) => typeof value === 'string'), `Invalid ${approved.role} custody signature chain`)

  const purposeMessage = textEncoder.encode(`${entry.purpose}:${bytesToHex(compressedSecp256k1(entry.kms_public_key))}`)
  const appPublicKey = recoverKmsPublicKey(purposeMessage, chain[0] as string)
  const rootMessage = concatBytes(textEncoder.encode('dstack-kms-issued:'), appId, appPublicKey)
  return { appPublicKey, rootPublicKey: bytesToHex(recoverKmsPublicKey(rootMessage, chain[1] as string)) }
}

/**
 * Verify the dstack `evidence` object of an ACI report against the quote's
 * RTMR3 and the pinned policy. `approvedKeys` are the keyset entries the
 * gateway verifier selected; each must have a KMS custody chain to the pinned
 * root. `declaredProvenance` is the report's `attestation.source_provenance`.
 */
export function verifyDstackEvidence(
  evidenceValue: unknown,
  quoteRtmr3: Uint8Array,
  approvedKeys: readonly ApprovedCustodyKey[],
  declaredProvenance: unknown,
  policy: PhalaModelPolicy,
): VerifiedDstackEvidence {
  assert(isRecord(evidenceValue), 'Missing dstack evidence')
  const evidence = evidenceValue
  assert(typeof evidence.event_log === 'string', 'Missing dstack event log')
  assert(typeof evidence.app_compose === 'string', 'Missing measured app Compose')

  let parsed: unknown
  try {
    parsed = JSON.parse(evidence.event_log)
  } catch {
    throw new Error('Dstack event log is not valid JSON')
  }
  assert(Array.isArray(parsed), 'Dstack event log is not an array')
  const events = parsed.map(asEvent)
  assert(equalBytes(replayRtmr(events, 3), quoteRtmr3), 'Dstack event log does not replay to quote RTMR3')

  const appIdBytes = hexToBytes(oneBeforeSystemReady(events, 'app-id').event_payload)
  const appId = bytesToHex(appIdBytes)
  const composeHash = bytesToHex(hexToBytes(oneBeforeSystemReady(events, 'compose-hash').event_payload))
  assert(appId === policy.appId, `Dstack app id is not approved: ${appId}`)
  assert(composeHash === policy.composeHash, `Dstack Compose hash is not approved: ${composeHash}`)
  assert(bytesToHex(sha256(textEncoder.encode(evidence.app_compose))) === composeHash, 'Dstack Compose preimage is not bound to the measured hash')
  const source = verifyMeasuredSourceProvenance(evidence.app_compose, policy)

  // §4.1: the declared provenance is unmeasured, so it must restate what the
  // measured Compose says; a report without it has no acceptable provenance.
  assert(isRecord(declaredProvenance), 'Phala report has no source provenance')
  assert(typeof declaredProvenance.repo_url === 'string' && stripGitSuffix(declaredProvenance.repo_url) === stripGitSuffix(source.sourceRepository), 'Declared source repository disagrees with the measured Compose')
  assert(declaredProvenance.repo_commit === source.sourceCommit, 'Declared source commit disagrees with the measured Compose')

  const custody = evidence.key_custody
  assert(isRecord(custody) && custody.provider === 'dstack-kms' && Array.isArray(custody.keys), 'Missing dstack KMS custody evidence')
  assert(approvedKeys.length > 0, 'No keys were approved for custody verification')
  let appPublicKey: Uint8Array | undefined
  let kmsRootPublicKey: string | undefined
  for (const approved of approvedKeys) {
    const link = verifyCustodyChain(custody.keys, approved, appIdBytes)
    assert(appPublicKey === undefined || equalBytes(appPublicKey, link.appPublicKey), 'Dstack KMS custody chains name different app keys')
    assert(kmsRootPublicKey === undefined || kmsRootPublicKey === link.rootPublicKey, 'Dstack KMS custody chains name different roots')
    appPublicKey = link.appPublicKey
    kmsRootPublicKey = link.rootPublicKey
  }
  assert(kmsRootPublicKey === policy.kmsRootPublicKey, `Dstack KMS root is not approved: ${kmsRootPublicKey}`)

  return { appId, composeHash, kmsRootPublicKey, ...source }
}
