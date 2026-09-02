import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'
import { bytesToHex, concatBytes, hexToBytes, textDecoder, textEncoder } from '../src/lib/encoding'
import { openE2eeChannel, requestAad, responseAad } from '../src/lib/phala-aci'
import type { ReportVerification } from '../src/lib/phala-aci/types'

const ALGO = 'x25519-aes-256-gcm-hkdf-sha256'
const SERVICE_SEED = new Uint8Array(32).fill(0x03)
const SERVICE_PUBLIC = bytesToHex(x25519.getPublicKey(SERVICE_SEED))
const bs = (bytes: Uint8Array): BufferSource => bytes as BufferSource

function verificationWithKeys(keys: Array<{ key_id: string; algo: string; public_key: string }>): ReportVerification {
  return {
    ok: true,
    checks: [],
    workloadKeysetDigest: 'sha256:' + '00'.repeat(32),
    keyset: { not_after: 4_102_444_800, receipt_signing_keys: [], e2ee_public_keys: keys },
  }
}

const approved = { keyId: 'approved', algorithm: ALGO, publicKey: SERVICE_PUBLIC }

async function aesKey(shared: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', bs(hkdf(sha256, shared, undefined, textEncoder.encode('aci.e2ee.v2.x25519'), 32)), 'AES-GCM', false, [usage])
}

/** The service side of e2ee-v2 §4: open a sealed request field with the fixed service seed. */
async function serviceOpen(blobHex: string, aad: Uint8Array): Promise<string> {
  const blob = hexToBytes(blobHex)
  const key = await aesKey(x25519.getSharedSecret(SERVICE_SEED, blob.slice(0, 32)), 'decrypt')
  return textDecoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bs(blob.slice(32, 44)), additionalData: bs(aad) }, key, bs(blob.slice(44))))
}

/** The service side of e2ee-v2 §4: seal a response field to the client's static key. */
async function serviceSeal(clientPublicHex: string, plaintext: string, aad: Uint8Array): Promise<string> {
  const ephemeral = x25519.utils.randomSecretKey()
  const key = await aesKey(x25519.getSharedSecret(ephemeral, hexToBytes(clientPublicHex)), 'encrypt')
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(iv), additionalData: bs(aad) }, key, bs(textEncoder.encode(plaintext))))
  return bytesToHex(concatBytes(x25519.getPublicKey(ephemeral), iv, ciphertext))
}

describe('Phala E2EE channel', () => {
  it('uses the exact verifier-approved key instead of the first matching algorithm', async () => {
    const verification = verificationWithKeys([
      { key_id: 'rotated-unapproved', algo: ALGO, public_key: bytesToHex(x25519.getPublicKey(x25519.utils.randomSecretKey())) },
      { key_id: 'approved', algo: ALGO, public_key: SERVICE_PUBLIC },
    ])
    const channel = await openE2eeChannel(verification, approved)
    const sealed = await channel.seal({ model: 'test/model', messages: [{ role: 'user', content: 'secret' }] })
    expect(sealed.headers['X-Model-Pub-Key']).toBe(SERVICE_PUBLIC)
  })

  it('refuses unverified reports and a missing, changed, or foreign approved key', async () => {
    const verification = verificationWithKeys([{ key_id: 'approved', algo: ALGO, public_key: SERVICE_PUBLIC }])
    await expect(openE2eeChannel({ ...verification, ok: false }, approved)).rejects.toThrow('not verified')
    await expect(openE2eeChannel({ ok: true, checks: [] }, approved)).rejects.toThrow('not verified')
    await expect(openE2eeChannel(verification, { ...approved, keyId: 'missing' })).rejects.toThrow('approved E2EE key')
    await expect(openE2eeChannel(verification, { ...approved, publicKey: '00'.repeat(32) })).rejects.toThrow('approved E2EE key')
    await expect(openE2eeChannel(verification, { ...approved, algorithm: 'x25519-chacha20-poly1305' })).rejects.toThrow('approved E2EE key')
    await expect(openE2eeChannel(verificationWithKeys([{ key_id: 'approved', algo: ALGO, public_key: '00'.repeat(31) }]), { ...approved, publicKey: '00'.repeat(31) })).rejects.toThrow('32 bytes')
  })

  it('round-trips a completion through the e2ee-v2 request and response constructions', async () => {
    const channel = await openE2eeChannel(verificationWithKeys([{ key_id: 'approved', algo: ALGO, public_key: SERVICE_PUBLIC }]), approved)
    const request = { model: 'test/model', messages: [{ role: 'user', content: 'secret prompt' }], stream: false, provider: { aci_verified: true } }
    const sealed = await channel.seal(request)
    const context = { algo: ALGO, model: 'test/model', nonce: sealed.headers['X-E2EE-Nonce']!, ts: Number(sealed.headers['X-E2EE-Timestamp']) }
    expect(sealed.body).toMatchObject({ model: 'test/model', stream: false, provider: { aci_verified: true } })
    const sealedContent = (sealed.body.messages as Array<{ role: string; content: string }>)[0]!
    expect(sealedContent.role).toBe('user')
    expect(await serviceOpen(sealedContent.content, requestAad({ ...context, field: 'messages.0.content' }))).toBe('secret prompt')

    const clientKey = sealed.headers['X-Client-Pub-Key']!
    const opened = await channel.open({
      id: 'chat-1',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: await serviceSeal(clientKey, 'answer', responseAad({ ...context, id: 'chat-1', field: 'choices.0.message.content' })),
          reasoning: await serviceSeal(clientKey, 'thinking', responseAad({ ...context, id: 'chat-1', field: 'choices.0.message.reasoning' })),
          reasoning_content: null,
        },
      }],
    })
    expect(opened).toEqual({ id: 'chat-1', choices: [{ index: 0, message: { role: 'assistant', content: 'answer', reasoning: 'thinking', reasoning_content: null } }] })
  })

  it('rejects response fields moved to another path, another request, or left in plaintext', async () => {
    const channel = await openE2eeChannel(verificationWithKeys([{ key_id: 'approved', algo: ALGO, public_key: SERVICE_PUBLIC }]), approved)
    const request = { model: 'test/model', messages: [{ role: 'user', content: 'secret' }] }
    const first = await channel.seal(request)
    const firstContext = { algo: ALGO, model: 'test/model', nonce: first.headers['X-E2EE-Nonce']!, ts: Number(first.headers['X-E2EE-Timestamp']) }
    const clientKey = first.headers['X-Client-Pub-Key']!
    const moved = await serviceSeal(clientKey, 'answer', responseAad({ ...firstContext, id: 'chat-1', field: 'choices.1.message.content' }))
    await expect(channel.open({ id: 'chat-1', choices: [{ index: 0, message: { content: moved } }] })).rejects.toThrow('choices.0.message.content is not ciphertext')

    const second = await channel.seal(request)
    const replayed = await serviceSeal(clientKey, 'answer', responseAad({ ...firstContext, id: 'chat-1', field: 'choices.0.message.content' }))
    await expect(channel.open({ id: 'chat-1', choices: [{ message: { content: replayed } }] })).rejects.toThrow('is not ciphertext')
    expect(second.headers['X-E2EE-Nonce']).not.toBe(first.headers['X-E2EE-Nonce'])

    await channel.seal(request)
    await expect(channel.open({ id: 'chat-1', choices: [{ index: 0, message: { reasoning: 'relay-visible reasoning' } }] })).rejects.toThrow('choices.0.message.reasoning is not ciphertext')
    for (const reasoning of [[], {}, 7]) {
      await channel.seal(request)
      await expect(channel.open({ id: 'chat-1', choices: [{ index: 0, message: { reasoning } }] })).rejects.toThrow('unsupported unencrypted response field')
    }
    await channel.seal(request)
    await expect(channel.open({ id: 'chat-1', choices: [{ index: 0, message: { audio: { data: 'ff' } } }] })).rejects.toThrow('choices.message.audio')
  })

  it('keeps the channel single-flight', async () => {
    const channel = await openE2eeChannel(verificationWithKeys([{ key_id: 'approved', algo: ALGO, public_key: SERVICE_PUBLIC }]), approved)
    const request = { model: 'test/model', messages: [{ role: 'user', content: 'secret' }] }
    await expect(channel.open({ id: 'chat-0', choices: [] })).rejects.toThrow('call seal first')
    await channel.seal(request)
    await expect(channel.seal(request)).rejects.toThrow('prior response is still pending')
    await channel.open({ id: 'chat-1', choices: [] })
    await expect(channel.open({ id: 'chat-1', choices: [] })).rejects.toThrow('call seal first')
  })

  it('refuses to seal request shapes other than the pinned chat-completion form', async () => {
    const channel = await openE2eeChannel(verificationWithKeys([{ key_id: 'approved', algo: ALGO, public_key: SERVICE_PUBLIC }]), approved)
    await expect(channel.seal({ model: 'test/model', prompt: 'completions-style secret' })).rejects.toThrow('request.messages must be an array')
    await expect(channel.seal({ messages: [] })).rejects.toThrow('request.model must be a string')
    await expect(channel.seal({ model: 'test/model', messages: [{ role: 'user', content: 'ok' }] })).resolves.toBeDefined()
  })
})
