/**
 * Report binding checks that need no hardware root: §9.1 check 2 (binding and
 * freshness: keyset bytes -> digest -> statement -> `report_data`) and check 3
 * (expiry), plus the aci/1 protocol gate (Appendix B). Check 1 (the TDX quote
 * verifies to the Intel root and binds `report_data`) and checks 4-6
 * (provenance, custody, channel) are composed by the verifier profile in
 * ../phala-verifier-core.ts.
 */

import { computeKeysetDigest, computeReportData } from './digest'
import type { AttestationReport, Check, ReportVerification, WorkloadKeyset } from './types'

/**
 * Keysets living longer than this are rejected as implausibly distant (§3.1).
 * The reference gateway issues keysets that expire within weeks; a year leaves
 * room for slower rotation without accepting an effectively unexpiring key.
 */
export const MAX_KEYSET_LIFETIME_SECONDS = 366 * 86_400

/** Options for {@link verifyReportBinding}. */
export interface ReportBindingOptions {
  /**
   * Current time in Unix seconds for the expiry check (§9.1 check 3).
   * Defaults to the local clock; pass an explicit value for deterministic tests.
   */
  now?: number
  /** Upper bound on `not_after - now`; defaults to {@link MAX_KEYSET_LIFETIME_SECONDS}. */
  maxKeysetLifetimeSeconds?: number
}

/**
 * Verify the report's cryptographic bindings for `nonce`, the value this
 * client sent to `GET /v1/aci/attestation`, or `null`/`undefined` when it sent
 * none (§3.2). One recomputation establishes that the keyset is exactly what
 * the quote bound and that the quote postdates the challenge (§9.1 check 2).
 *
 * Returns per-check results plus the established keyset (digest and parsed
 * form); a failed check on the served report is `ok: false`, never thrown.
 * The one exception is the caller's own input: a nonce that is not 64
 * lowercase hex throws {@link AciFormatError} (§3.2).
 */
export function verifyReportBinding(
  report: AttestationReport,
  nonce: string | null | undefined,
  options: ReportBindingOptions = {},
): ReportVerification {
  const now = options.now ?? Math.floor(Date.now() / 1000)
  const maxLifetime = options.maxKeysetLifetimeSeconds ?? MAX_KEYSET_LIFETIME_SECONDS
  const checks: Check[] = []

  // Protocol gate (Appendix B): artifacts with another version are rejected.
  const versionOk = report.api_version === 'aci/1'
  checks.push({
    name: 'api_version',
    ok: versionOk,
    ...(versionOk ? {} : { detail: `api_version "${String(report.api_version)}" is not "aci/1"` }),
  })

  const keysetValue: unknown = report.attestation?.workload_keyset
  if (keysetValue === null || typeof keysetValue !== 'object' || Array.isArray(keysetValue)) {
    const detail = 'workload_keyset is not a JSON object'
    for (const name of ['workload_keyset_digest', 'report_data', 'not_after', 'not_after_bound']) {
      checks.push({ name, ok: false, detail })
    }
    return { ok: false, checks }
  }

  // §9.1 check 2: recompute the whole chain from the served keyset object,
  // canonicalizing exactly what was parsed, unknown members included. The
  // recomputed digest is authoritative (Appendix A); the report's restated copy
  // is checked for consistency but never feeds the statement.
  const digest = computeKeysetDigest(keysetValue as WorkloadKeyset)
  pushEqual(checks, 'workload_keyset_digest', report.workload_keyset_digest, digest)
  const expectedReportData = computeReportData(digest, nonce)
  pushEqual(checks, 'report_data', report.attestation.report_data, expectedReportData)

  const keyset = keysetValue as WorkloadKeyset

  // §9.1 check 3: now < not_after in the decoded keyset, and the keyset is not
  // implausibly long-lived (§3.1).
  if (!Number.isSafeInteger(keyset.not_after)) {
    const detail = 'keyset has no integer not_after'
    checks.push({ name: 'not_after', ok: false, detail })
    checks.push({ name: 'not_after_bound', ok: false, detail })
  } else {
    const ok = now < keyset.not_after
    checks.push({
      name: 'not_after',
      ok,
      ...(ok ? {} : { detail: `now ${now} >= not_after ${keyset.not_after}` }),
    })
    const bounded = keyset.not_after - now <= maxLifetime
    checks.push({
      name: 'not_after_bound',
      ok: bounded,
      ...(bounded ? {} : { detail: `not_after ${keyset.not_after} is more than ${maxLifetime}s after now ${now}` }),
    })
  }

  return {
    ok: checks.every((c) => c.ok),
    checks,
    workloadKeysetDigest: digest,
    keyset,
  }
}

function pushEqual(checks: Check[], name: string, actual: unknown, expected: string): void {
  const ok = actual === expected
  checks.push({ name, ok, ...(ok ? {} : { detail: `report ${String(actual)} != recomputed ${expected}` }) })
}
