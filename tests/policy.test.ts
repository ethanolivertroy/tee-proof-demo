import { describe, expect, it } from 'vitest'
import { DEFAULT_MODEL_ID, getModelPolicy, MODEL_OPTIONS } from '../src/lib/policy'

describe('public model allowlist', () => {
  it('contains exactly one reviewed model per provider', () => {
    expect(MODEL_OPTIONS.map(({ id, label, providerLabel }) => ({ id, label, providerLabel }))).toEqual([
      { id: 'deepseek-v4-flash', label: 'DeepSeek V4 Flash', providerLabel: 'NEAR AI Cloud' },
      { id: 'phala-gpt-oss-20b', label: 'GPT-OSS 20B', providerLabel: 'Phala Cloud' },
    ])
    expect(DEFAULT_MODEL_ID).toBe('deepseek-v4-flash')
    expect(getModelPolicy('deepseek-v4-flash').endpointLabel).toBe('dsv4-flash.completions.near.ai')
    expect(getModelPolicy('phala-gpt-oss-20b').endpointLabel).toBe('inference.phala.com')
  })
})
