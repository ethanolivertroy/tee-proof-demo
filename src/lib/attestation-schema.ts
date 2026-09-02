export const NEAR_ATTESTATION_REQUIRED_FIELDS = [
  'model_name',
  'signing_algo',
  'signing_public_key',
  'signing_address',
  'request_nonce',
  'intel_quote',
  'nvidia_payload',
  'info',
] as const

export const NEAR_ATTESTATION_ALLOWED_FIELDS = [
  ...NEAR_ATTESTATION_REQUIRED_FIELDS,
  'event_log',
  'all_attestations',
  'compose_manager_attestation',
  'ohttp_key_config',
  'ohttp_attestation',
] as const
