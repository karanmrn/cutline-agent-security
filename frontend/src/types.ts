export type Event = {
  event_id: string
  session_id: string
  parent_event_id?: string | null
  sequence_number: number
  actor: string
  source_type: string
  source_trust: 'TRUSTED' | 'INTERNAL' | 'UNTRUSTED'
  data_class: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'SECRET'
  tool_name: string
  resource?: string | null
  destination?: string | null
  action_type:
    | 'READ'
    | 'WRITE'
    | 'EXECUTE'
    | 'EXTERNAL_WRITE'
    | 'DELETE'
    | 'CREDENTIAL_USE'
  arguments_redacted: Record<string, unknown>
  policy_decision: 'ALLOW' | 'DENY' | 'NOT_EVALUATED'
  outcome: string
  message: string
  timestamp: string
}

export type GraphNode = {
  id: string
  label: string
  kind: string
  status: 'safe' | 'danger' | 'blocked'
  event_id?: string | null
}

export type GraphEdge = {
  source: string
  target: string
  label: string
  status: 'safe' | 'danger' | 'blocked'
}

export type RunResult = {
  session_id: string
  mode: 'monitor' | 'enforce'
  provider: string
  status: string
  secret_exposed: boolean
  exfiltration_attempted: boolean
  exfiltration_blocked: boolean
  code_fixed: boolean
  tests_passed: boolean
  test_output: string
  collector_count: number
  events: Event[]
  graph: {
    nodes: GraphNode[]
    edges: GraphEdge[]
  }
}

export type PolicyCandidate = {
  id: string
  title: string
  effect: string
  disruption_score: number
  selected: boolean
}

export type ProposedPolicy = {
  id: string
  version: number
  policy_hash: string
  title: string
  description: string
  effect: 'DENY'
  match: {
    data_class: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'SECRET'
    action_type: string
    destination: 'NOT_IN_SESSION_ALLOWLIST'
  }
  disruption_score: number
  evidence_event_ids: string[]
  candidates: PolicyCandidate[]
  yaml: string
}

export type ReplayProvider = 'local' | 'modal'

export type RegressionOutcomes = {
  attack_blocked: boolean
  utility_retained: boolean
  tests_passed: boolean
}

export type RegressionManifest = {
  schema_version: '1.0'
  fixture_id: 'synthetic-poisoned-workspace-v1'
  source_session_id: string
  replay_session_id: string
  replay_provider: ReplayProvider
  policy_id: string
  policy_version: number
  policy_hash: string
  source_evidence_event_ids: string[]
  replay_evidence_event_ids: string[]
  expected: RegressionOutcomes
  actual: RegressionOutcomes
  status: 'VERIFIED'
  artifact_sha256: string
}

export type IntegrationState = 'disabled' | 'unverified' | 'ready' | 'error'

export type IntegrationStatus = {
  provider: string
  state: IntegrationState
  configured: boolean
  last_checked_at: string | null
  message: string | null
  enabled?: boolean
  error?: string | null
}

export type LegacyIntegrationStatus = {
  provider?: string
  configured: boolean
  last_checked_at?: string | null
  message?: string | null
  enabled: boolean
  error?: string | null
}

export type DemoState = {
  vulnerable_run: RunResult | null
  proposed_policy: ProposedPolicy | null
  replay_run: RunResult | null
  regression_manifest: RegressionManifest | null
  integrations: Record<string, IntegrationStatus | LegacyIntegrationStatus>
}
