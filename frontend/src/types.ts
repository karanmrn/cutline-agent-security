export type Event = {
  event_id: string
  sequence_number: number
  source_trust: 'TRUSTED' | 'INTERNAL' | 'UNTRUSTED'
  data_class: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'SECRET'
  tool_name: string
  resource?: string | null
  destination?: string | null
  action_type: string
  policy_decision: 'ALLOW' | 'DENY' | 'NOT_EVALUATED'
  outcome: string
  message: string
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

export type DemoState = {
  vulnerable_run: RunResult | null
  proposed_policy: ProposedPolicy | null
  replay_run: RunResult | null
  integrations: Record<
    string,
    { enabled: boolean; configured: boolean; error?: string | null }
  >
}
