import { describe, expect, it } from 'vitest'
import { openE2eeChannel } from '../src/lib/phala-aci/e2ee-channel'
import type { AttestationReport, ReportVerification } from '../src/lib/phala-aci/types'

const ALGO = 'x25519-aes-256-gcm-hkdf-sha256'

async function rawX25519PublicKey(): Promise<string> {
  const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as CryptoKeyPair
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  return [...raw].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function reportWithKeys(keys: Array<{ key_id: string; algo: string; public_key: string }>): AttestationReport {
  return {
    workload_keyset_digest: 'sha256:keyset',
    attestation: { workload_keyset: { e2ee_public_keys: keys } },
  } as unknown as AttestationReport
}

const verification = {
  ok: true,
  workloadKeysetDigest: 'sha256:keyset',
} as ReportVerification

describe('Phala E2EE channel key selection', () => {
  it('uses the exact verifier-approved key instead of the first matching algorithm', async () => {
    const first = await rawX25519PublicKey()
    const approved = await rawX25519PublicKey()
    const report = reportWithKeys([
      { key_id: 'rotated-unapproved', algo: ALGO, public_key: first },
      { key_id: 'approved', algo: ALGO, public_key: approved },
    ])

    const channel = await openE2eeChannel(report, verification, {
      keyId: 'approved',
      algorithm: ALGO,
      publicKey: approved,
    })
    const sealed = await channel.seal({ model: 'test/model', messages: [{ role: 'user', content: 'secret' }] })
    expect(sealed.headers['X-Model-Pub-Key']).toBe(approved)
  })

  it('rejects a missing or changed approved key', async () => {
    const approved = await rawX25519PublicKey()
    const report = reportWithKeys([{ key_id: 'approved', algo: ALGO, public_key: approved }])
    await expect(openE2eeChannel(report, verification, {
      keyId: 'missing',
      algorithm: ALGO,
      publicKey: approved,
    })).rejects.toThrow('approved E2EE key')
    await expect(openE2eeChannel(report, verification, {
      keyId: 'approved',
      algorithm: ALGO,
      publicKey: '00'.repeat(32),
    })).rejects.toThrow('approved E2EE key')
  })

  it('keeps request decryption state single-flight and rejects every plaintext reasoning value', async () => {
    const approved = await rawX25519PublicKey()
    const report = reportWithKeys([{ key_id: 'approved', algo: ALGO, public_key: approved }])
    const channel = await openE2eeChannel(report, verification, {
      keyId: 'approved',
      algorithm: ALGO,
      publicKey: approved,
    })
    const request = { model: 'test/model', messages: [{ role: 'user', content: 'secret' }] }

    await channel.seal(request)
    await expect(channel.seal(request)).rejects.toThrow('prior response is still pending')
    await expect(channel.open({
      id: 'chat-1',
      choices: [{ index: 0, message: { reasoning: 'relay-visible reasoning' } }],
    })).rejects.toThrow('unsupported unencrypted response field')

    for (const reasoning of [null, [], {}]) {
      await channel.seal(request)
      await expect(channel.open({
        id: 'chat-1',
        choices: [{ index: 0, message: { reasoning } }],
      })).rejects.toThrow('unsupported unencrypted response field')
    }
  })

  it('refuses to seal request shapes other than the pinned chat-completion form', async () => {
    const approved = await rawX25519PublicKey()
    const report = reportWithKeys([{ key_id: 'approved', algo: ALGO, public_key: approved }])
    const channel = await openE2eeChannel(report, verification, {
      keyId: 'approved',
      algorithm: ALGO,
      publicKey: approved,
    })
    await expect(channel.seal({ model: 'test/model', prompt: 'completions-style secret' }))
      .rejects.toThrow('request.messages must be an array')
  })
})
