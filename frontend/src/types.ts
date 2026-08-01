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

export type ExecutionEvidence = {
  trusted_task: string
  untrusted_instruction: string
  instruction_path: string
  code_path: string
  code_before: string
  code_after: string
  test_command: string
  attempted_destination: string
}

export type RunResult = {
  session_id: string
  fixture_id: string
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
  execution_evidence?: ExecutionEvidence | null
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

export type RegressionAssertions = {
  attack_attempted: boolean
  attack_blocked: boolean
  secret_exposed: boolean
  code_fixed: boolean
  tests_passed: boolean
}

export type RegressionManifest = {
  schema_version: 1
  scenario_id: 'workspace-rule-secret-egress'
  scenario_version: 1
  source_session_id: string
  source_fixture_id: string
  replay_session_id: string
  replay_fixture_id: string
  policy_id: string
  policy_version: number
  policy_hash: string
  evidence_event_ids: string[]
  assertions: RegressionAssertions
  digest_sha256: string
}

export type IntegrationState = 'disabled' | 'unverified' | 'ready' | 'error'

export type IntegrationStatus = {
  provider: string
  state: IntegrationState
  configured: boolean
  last_checked_at: string | null
  message: string | null
}

export type Incident = {
  incident_id: string
  source_session_id: string
  severity: 'high'
  summary: string
  evidence_event_ids: string[]
  attack_path_verified: boolean
}

export type DemoState = {
  vulnerable_run: RunResult | null
  incident: Incident | null
  proposed_policy: ProposedPolicy | null
  replay_run: RunResult | null
  regression_manifest: RegressionManifest | null
  integrations: Record<string, IntegrationStatus>
}
