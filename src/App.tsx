import { useEffect, useState, type FormEvent } from 'react'
import { establishTrust, evidenceIsFresh, sendEncryptedPrompt, verifyDemoAccess, type TrustStage } from './lib/api'
import { shortHex } from './lib/encoding'
import { DEFAULT_MODEL_ID, getModelPolicy, isNearPolicy, MODEL_OPTIONS, type ModelId } from './lib/policy'
import type { CompletionReceipt, TrustEvidence } from './lib/types'

type VerificationState = 'idle' | TrustStage | 'failed'

function StatusMark({ state }: { state: 'waiting' | 'working' | 'passed' | 'failed' }) {
  const symbols = { waiting: '·', working: '↻', passed: '✓', failed: '!' }
  return <span className={`status-mark status-${state}`} aria-hidden="true">{symbols[state]}</span>
}

function CheckRow({ label, detail, state }: { label: string; detail: string; state: 'waiting' | 'working' | 'passed' | 'failed' }) {
  return (
    <div className="check-row">
      <StatusMark state={state} />
      <div><strong>{label}</strong><span>{detail}</span></div>
    </div>
  )
}

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1_500)
  }
  return (
    <div className="receipt-row">
      <span>{label}</span>
      <button type="button" className="hash-button" onClick={copy} title={value}>
        <code>{shortHex(value, 10)}</code><small>{copied ? 'copied' : 'copy'}</small>
      </button>
    </div>
  )
}

function App() {
  const [modelId, setModelId] = useState<ModelId>(DEFAULT_MODEL_ID)
  const [accessToken, setAccessToken] = useState('')
  const [accessGranted, setAccessGranted] = useState(false)
  const [checkingAccess, setCheckingAccess] = useState(false)
  const [verification, setVerification] = useState<VerificationState>('idle')
  const [evidence, setEvidence] = useState<TrustEvidence | null>(null)
  const [prompt, setPrompt] = useState('Explain confidential computing in two sentences.')
  const [answer, setAnswer] = useState('')
  const [receipt, setReceipt] = useState<CompletionReceipt | null>(null)
  const [error, setError] = useState('')
  const [sending, setSending] = useState(false)
  const [clock, setClock] = useState(Date.now())
  const policy = getModelPolicy(modelId)
  const near = isNearPolicy(policy)

  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 10_000)
    return () => window.clearInterval(timer)
  }, [])

  const fresh = evidence ? evidenceIsFresh(evidence, clock) : false
  const ready = accessGranted && verification === 'ready' && fresh && evidence?.modelId === modelId
  const verifying = ['fetching', 'cpu', 'gpu'].includes(verification)
  const cpuPassed = verification === 'gpu' || verification === 'ready'
  const platformPassed = verification === 'ready'

  function resetProof(nextModelId = modelId) {
    setModelId(nextModelId)
    setVerification('idle')
    setEvidence(null)
    setAnswer('')
    setReceipt(null)
    setError('')
  }

  async function unlock(event: FormEvent) {
    event.preventDefault()
    setCheckingAccess(true)
    setAccessGranted(false)
    setError('')
    resetProof()
    try {
      await verifyDemoAccess(accessToken)
      setAccessGranted(true)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Access token was rejected')
    } finally {
      setCheckingAccess(false)
    }
  }

  async function verify() {
    if (!accessGranted) return
    setEvidence(null)
    setAnswer('')
    setReceipt(null)
    setError('')
    setVerification('fetching')
    try {
      const result = await establishTrust(modelId, setVerification)
      setEvidence(result)
      setClock(Date.now())
    } catch (reason) {
      setVerification('failed')
      setError(reason instanceof Error ? reason.message : 'Environment verification failed')
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!evidence || !ready || sending) return
    setSending(true)
    setAnswer('')
    setReceipt(null)
    setError('')
    try {
      const result = await sendEncryptedPrompt(prompt, evidence, accessToken)
      setAnswer(result.content)
      setReceipt(result.receipt)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Encrypted request failed')
    } finally {
      setSending(false)
    }
  }

  const proofState = verification === 'failed' ? 'failed' : ready ? 'passed' : verifying ? 'working' : 'waiting'

  return (
    <div className="site-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="TEE Proof home"><span className="shield">✓</span><span>TEE Proof</span></a>
        <div className={`top-status ${ready ? 'is-ready' : ''}`}>
          <span className="status-dot" />
          {!accessGranted ? 'Access locked' : ready ? 'Environment verified' : verification === 'failed' ? 'Verification blocked' : verifying ? 'Verification running' : 'Not verified'}
        </div>
      </header>

      <main>
        <section className="hero" aria-labelledby="page-title">
          <p className="eyebrow">Browser-verified confidential inference</p>
          <h1 id="page-title">Verify first.<br /><span>Encrypt second.</span></h1>
          <p className="hero-copy">Your browser verifies fresh confidential-computing evidence before releasing one synthetic prompt to {policy.label} on {policy.providerLabel}.</p>
          <div className="scope-note"><strong>Public proof:</strong> use synthetic data only. This is not a production secret-release system.</div>
        </section>

        <section className={`access-panel ${accessGranted ? 'is-unlocked' : ''}`} aria-labelledby="access-title">
          <div><p className="panel-kicker">Owner gate</p><h2 id="access-title">Protect provider spend</h2><p>The paid relay routes reject requests unless this deployment secret matches.</p></div>
          <form onSubmit={unlock}>
            <label htmlFor="access-token">Demo access token</label>
            <div className="access-controls">
              <input
                id="access-token"
                type="password"
                value={accessToken}
                minLength={20}
                maxLength={256}
                autoComplete="current-password"
                onChange={(event) => { setAccessToken(event.target.value); setAccessGranted(false); resetProof() }}
                placeholder="Token set during deployment"
              />
              <button className="primary-button" type="submit" disabled={checkingAccess || accessToken.length < 20}>{checkingAccess ? 'Checking…' : accessGranted ? 'Unlocked' : 'Unlock demo'}</button>
            </div>
            <small>Kept only in this browser tab. Cloudflare Access can be added in front of the Worker for identity-based SSO.</small>
          </form>
        </section>

        <section className="model-section" aria-labelledby="model-title">
          <div className="model-heading"><div><p className="panel-kicker">Choose one reviewed route</p><h2 id="model-title">Two providers, two fixed policies</h2></div><span>Changing models clears prior evidence</span></div>
          <div className="model-options" role="radiogroup" aria-label="Reviewed confidential models">
            {MODEL_OPTIONS.map((option) => (
              <button
                type="button"
                role="radio"
                aria-checked={modelId === option.id}
                className={`model-option ${modelId === option.id ? 'is-selected' : ''}`}
                key={option.id}
                disabled={verifying || sending}
                onClick={() => resetProof(option.id)}
              >
                <span>{option.providerLabel}</span><strong>{option.label}</strong><code>{option.model}</code><small>{option.protocol}</small>
              </button>
            ))}
          </div>
        </section>

        <section className="proof-grid" aria-label="Confidential inference proof">
          <aside className="proof-panel">
            <div className="panel-heading"><div><p className="panel-kicker">Step 1</p><h2>Trust the evidence</h2></div><StatusMark state={proofState} /></div>
            <div className="checks" aria-live="polite">
              <CheckRow label="Fresh challenge" detail="32-byte browser nonce" state={verification === 'idle' ? 'waiting' : verification === 'failed' ? 'failed' : verification === 'fetching' ? 'working' : 'passed'} />
              <CheckRow label="Intel TDX" detail={near ? 'Quote, debug state, and measurements' : 'Gateway quote, event log, and measurements'} state={verification === 'cpu' ? 'working' : cpuPassed ? 'passed' : verification === 'failed' ? 'failed' : 'waiting'} />
              <CheckRow label={near ? 'NVIDIA GPU' : 'dstack + KMS'} detail={near ? `${policy.gpuCount} ${policy.gpuArchitecture.toLowerCase()} devices, signed verdicts` : 'Measured source, Compose, and key custody'} state={verification === 'gpu' ? 'working' : platformPassed ? 'passed' : verification === 'failed' ? 'failed' : 'waiting'} />
              <CheckRow label={near ? 'Model key' : 'Gateway keys'} detail={near ? 'Bound to nonce and approved workload' : 'E2EE and receipt keys bound to quote'} state={platformPassed ? 'passed' : verification === 'failed' ? 'failed' : 'waiting'} />
            </div>
            <button className="primary-button verify-button" type="button" onClick={verify} disabled={!accessGranted || verifying || sending}>{verifying ? 'Verifying environment…' : ready ? 'Verify again' : 'Verify environment'}</button>
            {!accessGranted && <p className="locked-help">Unlock the owner gate before verifying.</p>}
            {evidence && ready && (
              <details className="evidence-details">
                <summary>Verified evidence</summary>
                {evidence.protocol === 'near-e2ee-v2' ? (
                  <dl>
                    <div><dt>Provider</dt><dd>NEAR AI Cloud</dd></div><div><dt>Model</dt><dd>{evidence.model}</dd></div>
                    <div><dt>TDX status</dt><dd>{evidence.cpu.tcbStatus}</dd></div><div><dt>GPU model</dt><dd>{evidence.gpu.models.join(', ')}</dd></div>
                    <div><dt>Expires</dt><dd>{new Date(evidence.expiresAt).toLocaleTimeString()}</dd></div><div><dt>Quote</dt><dd><code>{shortHex(evidence.cpu.quoteHash)}</code></dd></div>
                    <div><dt>Policy</dt><dd><code>{shortHex(evidence.policyDigest)}</code></dd></div><div><dt>Nonce</dt><dd><code>{shortHex(evidence.nonce)}</code></dd></div>
                  </dl>
                ) : (
                  <dl>
                    <div><dt>Provider</dt><dd>Phala Cloud</dd></div><div><dt>Model</dt><dd>{evidence.model}</dd></div>
                    <div><dt>TDX status</dt><dd>{evidence.gateway.tcbStatus}</dd></div><div><dt>Workload</dt><dd><code>{shortHex(evidence.gateway.workloadId)}</code></dd></div>
                    <div><dt>Expires</dt><dd>{new Date(evidence.expiresAt).toLocaleTimeString()}</dd></div><div><dt>Quote</dt><dd><code>{shortHex(evidence.gateway.quoteHash)}</code></dd></div>
                    <div><dt>Policy</dt><dd><code>{shortHex(evidence.policyDigest)}</code></dd></div><div><dt>Nonce</dt><dd><code>{shortHex(evidence.nonce)}</code></dd></div>
                  </dl>
                )}
              </details>
            )}
          </aside>

          <section className={`prompt-panel ${ready ? 'is-unlocked' : ''}`}>
            <div className="panel-heading"><div><p className="panel-kicker">Step 2</p><h2>Release one prompt</h2></div><span className="lock-state">{ready ? 'Unlocked' : 'Locked'}</span></div>
            <form onSubmit={submit}>
              <label htmlFor="prompt">Synthetic prompt</label>
              <textarea id="prompt" value={prompt} onChange={(event) => setPrompt(event.target.value)} maxLength={2_000} rows={7} disabled={!ready || sending} aria-describedby="prompt-help" />
              <div className="field-meta" id="prompt-help"><span>{ready ? 'Encrypted in this browser before network release.' : 'Unlock and verify the selected route first.'}</span><span>{prompt.length}/2000</span></div>
              <button className="primary-button send-button" type="submit" disabled={!ready || sending || prompt.trim().length === 0}>{sending ? 'Encrypting and sending…' : 'Encrypt and send'}</button>
            </form>
          </section>
        </section>

        {error && <div className="error-card" role="alert"><strong>Blocked</strong><span>{error}</span></div>}

        {answer && receipt && (
          <section className="result-section" aria-live="polite">
            <div className="result-copy"><p className="panel-kicker">Step 3</p><h2>Verified completion</h2><p>{answer}</p></div>
            <div className="receipt-card">
              <div className="receipt-title"><StatusMark state="passed" /><strong>Exact response authenticated</strong></div>
              <CopyValue label="Request SHA-256" value={receipt.requestHash} /><CopyValue label="Response SHA-256" value={receipt.responseHash} />
              <CopyValue label="Attested signer" value={receipt.signer} /><CopyValue label="Signature" value={receipt.signature} />
              <p className="receipt-time">Verified {new Date(receipt.verifiedAt).toLocaleString()}</p>
            </div>
          </section>
        )}

        <section className="boundary-section">
          <p className="panel-kicker">The boundary</p>
          <div className="flow"><div><strong>Browser</strong><span>verify · encrypt · decrypt</span></div><i>ciphertext →</i><div><strong>Cloudflare</strong><span>access gate · relay</span></div><i>ciphertext →</i><div><strong>TEE</strong><span>decrypt · infer · sign</span></div></div>
          <p>The relay transports encrypted bodies and rejects paid routes without the owner token. Traffic metadata and provider billing data are outside this proof.</p>
        </section>
      </main>

      <footer><span>Apache-2.0 · Synthetic data only</span><a href="https://github.com/ethanolivertroy/tee-proof-demo" rel="noreferrer">Source and deploy button ↗</a></footer>
    </div>
  )
}

export default App
