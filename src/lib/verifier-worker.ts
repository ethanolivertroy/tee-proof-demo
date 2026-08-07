/// <reference lib="webworker" />

const VERIFIER_TIMEOUT_MS = 90_000

export type VerifierWorkerReply<TResult> =
  | { ok: true; result: TResult }
  | { ok: false; error: string }

/**
 * Run one verification request in a dedicated module worker and settle with
 * its reply, a timeout, or a worker failure. The caller supplies `createWorker`
 * so the `new Worker(new URL(..., import.meta.url))` pattern stays syntactically
 * intact at the call site for Vite's static worker bundling.
 */
export function runVerifierInWorker<TRequest, TResult>(
  createWorker: () => Worker,
  request: TRequest,
  label: string,
): Promise<TResult> {
  return new Promise((resolve, reject) => {
    const worker = createWorker()
    const timer = setTimeout(() => {
      worker.terminate()
      reject(new Error(`${label} timed out`))
    }, VERIFIER_TIMEOUT_MS)
    const settle = (outcome: () => void) => {
      clearTimeout(timer)
      worker.terminate()
      outcome()
    }
    worker.onmessage = (event: MessageEvent<VerifierWorkerReply<TResult>>) => settle(() => {
      if (event.data.ok) resolve(event.data.result)
      else reject(new Error(event.data.error || `${label} failed`))
    })
    worker.onerror = () => settle(() => reject(new Error(`${label} worker failed`)))
    worker.postMessage(request)
  })
}

/** Wire a worker entry module: run `verify` for each request and post the reply. */
export function wireVerifierWorker<TRequest, TResult>(
  verify: (request: TRequest) => Promise<TResult>,
  fallbackError: string,
): void {
  self.onmessage = async (event: MessageEvent<TRequest>) => {
    let reply: VerifierWorkerReply<TResult>
    try {
      reply = { ok: true, result: await verify(event.data) }
    } catch (error) {
      reply = { ok: false, error: error instanceof Error ? error.message : fallbackError }
    }
    self.postMessage(reply)
  }
}
