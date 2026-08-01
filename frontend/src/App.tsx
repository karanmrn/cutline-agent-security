import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Ban,
  Check,
  ChevronRight,
  CircleAlert,
  Code2,
  Database,
  Download,
  FileCheck2,
  Play,
  RefreshCcw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { api } from './api'
import type {
  DemoState,
  Event,
  GraphNode,
  IntegrationState,
  IntegrationStatus,
  ProposedPolicy,
  RegressionManifest,
  ReplayProvider,
  RunResult,
} from './types'

const emptyState: DemoState = {
  vulnerable_run: null,
  incident: null,
  proposed_policy: null,
  replay_run: null,
  regression_manifest: null,
  integrations: {},
}

const syntheticCanaryPattern = /CUTLINE_CANARY_[A-Z0-9]+/g

function redactText(value: string | null | undefined, fallback = '') {
  return value ? value.replace(syntheticCanaryPattern, '[REDACTED]') : fallback
}

function normalizedIntegrationState(
  status: IntegrationStatus | undefined,
): IntegrationState {
  return status?.state ?? 'disabled'
}

function statusMessage(status: IntegrationStatus | undefined) {
  return redactText(status?.message)
}

function providerReady(state: DemoState, provider: ReplayProvider) {
  return normalizedIntegrationState(state.integrations[provider]) === 'ready'
}

function providerSelectable(state: DemoState, provider: ReplayProvider) {
  const integration = state.integrations[provider]
  const status = normalizedIntegrationState(integration)
  return (
    status === 'ready' ||
    (provider === 'modal' && status === 'unverified' && integration?.configured)
  )
}

function Outcome({
  label,
  value,
  expected,
  known,
}: {
  label: string
  value: boolean
  expected: boolean
  known: boolean
}) {
  const tone = !known ? 'unknown' : value === expected ? 'safe' : 'danger'
  const displayedValue = known ? (value ? 'YES' : 'NO') : 'NOT RUN'
  return (
    <div
      aria-label={`${label}: ${known ? (value ? 'yes' : 'no') : 'not run'}`}
      className={`outcome-row ${tone}`}
    >
      <span>{label}</span>
      <strong>{displayedValue}</strong>
    </div>
  )
}

function RunCard({ title, run }: { title: string; run: RunResult | null }) {
  return (
    <article className="panel result-card">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">{title}</span>
          <h3>{redactText(run?.status, 'Waiting')}</h3>
        </div>
        <span
          aria-hidden="true"
          className={`status-dot ${run?.secret_exposed ? 'danger' : run ? 'safe' : ''}`}
        />
      </div>
      <div className="outcomes">
        <Outcome
          expected={false}
          known={Boolean(run)}
          label="Synthetic secret exposed"
          value={Boolean(run?.secret_exposed)}
        />
        <Outcome
          expected
          known={Boolean(run)}
          label="Exfiltration blocked"
          value={Boolean(run?.exfiltration_blocked)}
        />
        <Outcome
          expected
          known={Boolean(run)}
          label="Application fixed"
          value={Boolean(run?.code_fixed)}
        />
        <Outcome
          expected
          known={Boolean(run)}
          label="Tests passed"
          value={Boolean(run?.tests_passed)}
        />
      </div>
      <div className="provider-row">
        <span>Provider</span>
        <strong>{redactText(run?.provider, '-')}</strong>
      </div>
    </article>
  )
}

function NodeCard({ node }: { node: GraphNode }) {
  const icon =
    node.kind === 'instruction' ? (
      <Sparkles size={16} />
    ) : node.kind === 'data' ? (
      <Database size={16} />
    ) : node.kind === 'sink' ? (
      node.status === 'blocked' ? <Ban size={16} /> : <CircleAlert size={16} />
    ) : node.kind === 'action' ? (
      <Code2 size={16} />
    ) : (
      <Check size={16} />
    )

  return (
    <div className={`graph-node ${node.status}`}>
      <div className="node-icon" aria-hidden="true">
        {icon}
      </div>
      <div>
        <strong>{redactText(node.label)}</strong>
        <span>
          {node.event_id ? `Evidence: ${redactText(node.event_id)}` : 'Product path'}
        </span>
      </div>
    </div>
  )
}

function AttackPath({
  incident,
  replay,
}: {
  incident: RunResult | null
  replay: RunResult | null
}) {
  const run = replay ?? incident
  const dangerous = useMemo(
    () =>
      run?.graph.nodes.filter((node) =>
        ['workspace-rule', 'secret-read', 'external-write'].includes(node.id),
      ) ?? [],
    [run],
  )
  const legitimate = useMemo(
    () =>
      run?.graph.nodes.filter((node) =>
        ['user-task', 'code-fix', 'tests'].includes(node.id),
      ) ?? [],
    [run],
  )

  const path = (nodes: GraphNode[], label: string) => (
    <div aria-label={label} className="path-row" role="group">
      {nodes.map((node, index) => {
        const nextNode = nodes[index + 1]
        const edge = nextNode
          ? run?.graph.edges.find(
              (candidate) => candidate.source === node.id && candidate.target === nextNode.id,
            )
          : undefined
        return (
          <div className="path-segment" key={node.id}>
            <NodeCard node={node} />
            {edge && (
              <div className={`path-connector ${edge.status}`}>
                <span>{redactText(edge.label)}</span>
                <ChevronRight aria-hidden="true" className="path-arrow" size={22} />
              </div>
            )}
          </div>
        )
      })}
    </div>
  )

  return (
    <article
      aria-label="Attack path visualization"
      className="panel graph-panel"
      role="region"
    >
      <div className="panel-heading">
        <div>
          <span className="eyebrow">{replay ? 'Replay attack path' : 'Evidence graph'}</span>
          <h3>{replay ? 'Attack blocked. Task intact.' : 'Two paths. One task.'}</h3>
        </div>
        <Activity aria-hidden="true" size={20} />
      </div>
      {!run ? (
        <div className="empty">Run the compromised agent to reconstruct the path.</div>
      ) : (
        <div className="graph-lanes">
          <div className="graph-lane">
            <span className="lane-label danger-text">Harmful path</span>
            {path(dangerous, 'Harmful path')}
          </div>
          <div className="graph-lane">
            <span className="lane-label safe-text">Legitimate path</span>
            {path(legitimate, 'Legitimate path')}
          </div>
        </div>
      )}
    </article>
  )
}

function TimelineEvent({ event }: { event: Event }) {
  const severity =
    event.policy_decision === 'DENY'
      ? 'blocked'
      : event.source_trust === 'UNTRUSTED' || event.data_class === 'SECRET'
        ? 'danger'
        : 'safe'
  return (
    <div className={`timeline-event ${severity}`}>
      <div className="timeline-index">{String(event.sequence_number).padStart(2, '0')}</div>
      <div className="timeline-body">
        <div className="timeline-title">
          <strong>{redactText(event.tool_name)}</strong>
          <code>{redactText(event.event_id)}</code>
        </div>
        <p>{redactText(event.message)}</p>
        <div className="tags" aria-label="Evidence classifications">
          <span>{event.source_trust}</span>
          <span>{event.data_class}</span>
          <span>{event.action_type}</span>
          <span>{event.policy_decision}</span>
        </div>
      </div>
    </div>
  )
}

function CompromisedExecution({ run }: { run: RunResult | null }) {
  const evidence = run?.execution_evidence

  return (
    <section
      aria-label="Compromised agent execution"
      className="panel execution-panel"
      role="region"
    >
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Monitor-mode evidence</span>
          <h3>Compromised agent execution</h3>
        </div>
        <Code2 aria-hidden="true" size={20} />
      </div>
      {!run ? (
        <div className="empty">Run the compromised agent to inspect its safe execution record.</div>
      ) : !evidence ? (
        <div className="empty">Structured execution evidence is unavailable for this run.</div>
      ) : (
        <>
          <div className="execution-summary">
            <div aria-label="Trusted task" className="execution-callout trusted">
              <span>Trusted task</span>
              <p>{redactText(evidence.trusted_task)}</p>
            </div>
            <div
              aria-label="Injected repository instruction"
              className="execution-callout injected"
            >
              <span>Injected repository instruction</span>
              <blockquote>{redactText(evidence.untrusted_instruction)}</blockquote>
            </div>
          </div>

          <div className="execution-metadata">
            <div aria-label="Instruction path">
              <span>Instruction path</span>
              <code>{redactText(evidence.instruction_path)}</code>
            </div>
            <div>
              <span>Code path</span>
              <code>{redactText(evidence.code_path)}</code>
            </div>
            <div aria-label="Attempted destination">
              <span>Attempted destination</span>
              <code>{redactText(evidence.attempted_destination)}</code>
            </div>
          </div>

          <div className="execution-detail-grid">
            <div>
              <span className="execution-section-label">Application correction</span>
              <div className="execution-code-diff">
                <div aria-label="Code before" className="execution-code before">
                  <span>Before</span>
                  <pre>{redactText(evidence.code_before)}</pre>
                </div>
                <div aria-label="Code after" className="execution-code after">
                  <span>After</span>
                  <pre>{redactText(evidence.code_after)}</pre>
                </div>
              </div>
            </div>

            <div>
              <span className="execution-section-label">Redacted action log</span>
              <ul aria-label="Redacted action log" className="execution-actions">
                {run.events.map((event) => (
                  <li
                    aria-label={`Action ${redactText(event.tool_name)}`}
                    className="execution-action"
                    key={event.event_id}
                  >
                    <strong>{redactText(event.tool_name)}</strong>
                    <span>
                      Evidence <code>{redactText(event.event_id)}</code>
                    </span>
                    <span>
                      Decision <code>{redactText(event.policy_decision)}</code>
                    </span>
                    <span>
                      Outcome <code>{redactText(event.outcome)}</code>
                    </span>
                    <span>
                      Resource <code>{redactText(event.resource, '-')}</code>
                    </span>
                    <span>
                      Destination <code>{redactText(event.destination, '-')}</code>
                    </span>
                    <span>
                      Arguments{' '}
                      <code>{redactText(JSON.stringify(event.arguments_redacted), '{}')}</code>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div aria-label="Test result" className="execution-test-result">
            <div>
              <span>Test command</span>
              <code>{redactText(evidence.test_command)}</code>
            </div>
            <pre>{redactText(run.test_output, 'No test output recorded.')}</pre>
          </div>
        </>
      )}
    </section>
  )
}

function CandidateComparison({ policy }: { policy: ProposedPolicy }) {
  if (!policy.candidates.length) return null

  return (
    <div className="table-scroll">
      <table className="candidate-table">
        <caption>Candidate disruption comparison</caption>
        <thead>
          <tr>
            <th scope="col">Candidate</th>
            <th scope="col">Effect</th>
            <th scope="col">Cost</th>
            <th scope="col">Decision</th>
          </tr>
        </thead>
        <tbody>
          {policy.candidates.map((candidate) => (
            <tr className={candidate.selected ? 'selected-candidate' : ''} key={candidate.id}>
              <td>{redactText(candidate.title)}</td>
              <td>{redactText(candidate.effect)}</td>
              <td>{candidate.disruption_score}</td>
              <td>{candidate.selected ? <strong>Selected</strong> : 'Rejected'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ProviderSelector({
  state,
  selected,
  onSelect,
}: {
  state: DemoState
  selected: ReplayProvider
  onSelect: (provider: ReplayProvider) => void
}) {
  const providers: Array<{ id: ReplayProvider; label: string }> = [
    { id: 'local', label: 'Local' },
    { id: 'modal', label: 'Modal' },
  ]

  return (
    <fieldset className="provider-selector">
      <legend>Replay provider</legend>
      <div className="provider-options">
        {providers.map(({ id, label }) => {
          const integration = state.integrations[id]
          const status = normalizedIntegrationState(integration)
          const reason = statusMessage(integration)
          const ready = status === 'ready'
          const selectable = providerSelectable(state, id)
          return (
            <div className={`provider-option ${selected === id ? 'selected' : ''}`} key={id}>
              <div className="provider-option-line">
                <input
                  checked={selected === id}
                  disabled={!selectable}
                  id={`provider-${id}`}
                  name="replay-provider"
                  onChange={() => onSelect(id)}
                  type="radio"
                  value={id}
                />
                <label htmlFor={`provider-${id}`}>{label}</label>
                <span className={`provider-state ${status}`}>{status}</span>
              </div>
              {!ready && reason && <p className="provider-reason">{reason}</p>}
            </div>
          )
        })}
      </div>
    </fieldset>
  )
}

function PolicyPanel({
  policy,
  state,
  selectedProvider,
  onProviderChange,
}: {
  policy: ProposedPolicy | null
  state: DemoState
  selectedProvider: ReplayProvider
  onProviderChange: (provider: ReplayProvider) => void
}) {
  return (
    <article aria-label="Guardrail policy" className="panel policy-panel" role="region">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Least-disruptive control</span>
          <h3>{redactText(policy?.title, 'No guardrail generated')}</h3>
        </div>
        {policy && <div className="score">Cost {policy.disruption_score}</div>}
      </div>
      {!policy ? (
        <div className="empty">Generate a guardrail after the incident run.</div>
      ) : (
        <>
          <div className="policy-lineage" aria-label="Approved policy identity">
            <span>Version {policy.version}</span>
            <code title={redactText(policy.policy_hash)}>
              {redactText(policy.policy_hash.slice(0, 12))}…
            </code>
          </div>
          <p className="policy-description">{redactText(policy.description)}</p>
          <div className="evidence-row">
            <span>Source evidence</span>
            <div>
              {policy.evidence_event_ids.map((eventId) => (
                <code key={eventId}>Evidence {redactText(eventId)}</code>
              ))}
            </div>
          </div>
          <CandidateComparison policy={policy} />
          <pre>{redactText(policy.yaml)}</pre>
          {state.replay_run ? (
            <div aria-label="Completed replay provider" className="completed-replay-provider">
              <span>Completed replay provider</span>
              <strong>{redactText(state.replay_run.provider)}</strong>
            </div>
          ) : (
            <>
              <ProviderSelector
                onSelect={onProviderChange}
                selected={selectedProvider}
                state={state}
              />
              <div aria-label="Approval status" className="approval-status">
                <span>Approval status</span>
                <strong>AWAITING APPROVAL</strong>
              </div>
              <p className="approval-note" id="replay-approval">
                Approval binds this exact policy version and hash to one fresh{' '}
                {redactText(selectedProvider)} replay.
              </p>
            </>
          )}
        </>
      )}
    </article>
  )
}

function EvidencePanel({
  incident,
  replay,
  selected,
  onSelect,
}: {
  incident: RunResult | null
  replay: RunResult | null
  selected: 'incident' | 'replay'
  onSelect: (value: 'incident' | 'replay') => void
}) {
  const activeKind = selected === 'replay' && replay ? 'replay' : 'incident'
  const activeTrace = activeKind === 'replay' ? replay : incident
  const title = activeKind === 'replay' ? 'Replay evidence' : 'Incident evidence'

  return (
    <article className="panel timeline-panel">
      <div className="panel-heading evidence-heading">
        <div>
          <span className="eyebrow">Completed trace</span>
          <h3>{title}</h3>
        </div>
        <span className="event-count">{activeTrace?.events.length ?? 0} events</span>
      </div>
      <div className="evidence-switch" aria-label="Execution evidence" role="group">
        <button
          aria-pressed={activeKind === 'incident'}
          disabled={!incident}
          onClick={() => onSelect('incident')}
          type="button"
        >
          Incident evidence
        </button>
        <button
          aria-pressed={activeKind === 'replay'}
          disabled={!replay}
          onClick={() => onSelect('replay')}
          type="button"
        >
          Replay evidence
        </button>
      </div>
      <div className="timeline">
        {activeTrace?.events.length ? (
          activeTrace.events.map((event) => (
            <TimelineEvent event={event} key={event.event_id} />
          ))
        ) : (
          <div className="empty">Execution evidence will appear here.</div>
        )}
      </div>
    </article>
  )
}

function ManifestAssertion({
  label,
  value,
  passesWhen = true,
}: {
  label: string
  value: boolean
  passesWhen?: boolean
}) {
  return (
    <span className={value === passesWhen ? 'safe-text' : 'danger-text'}>
      {label}: {value ? 'yes' : 'no'}
    </span>
  )
}

function RegressionManifestPanel({ manifest }: { manifest: RegressionManifest }) {
  return (
    <article className="panel manifest-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Regression evidence</span>
          <h3>Regression manifest</h3>
        </div>
        <strong className="manifest-status">
          <FileCheck2 aria-hidden="true" size={14} />
          Schema v{manifest.schema_version}
        </strong>
      </div>
      <dl className="manifest-details">
        <div>
          <dt>Scenario</dt>
          <dd>
            <span>{redactText(manifest.scenario_id)}</span> v{manifest.scenario_version}
          </dd>
        </div>
        <div>
          <dt>Policy</dt>
          <dd>
            {redactText(manifest.policy_id)} v{manifest.policy_version}
          </dd>
        </div>
        <div>
          <dt>Source session</dt>
          <dd>{redactText(manifest.source_session_id)}</dd>
        </div>
        <div>
          <dt>Replay session</dt>
          <dd>{redactText(manifest.replay_session_id)}</dd>
        </div>
        <div className="manifest-fixtures manifest-wide">
          <dt>Fresh fixture pair</dt>
          <dd>
            <span>
              <small>Source fixture</small>
              <code>{redactText(manifest.source_fixture_id)}</code>
            </span>
            <span aria-hidden="true" className="fixture-arrow">→</span>
            <span>
              <small>Replay fixture</small>
              <code>{redactText(manifest.replay_fixture_id)}</code>
            </span>
          </dd>
        </div>
        <div className="manifest-wide">
          <dt>Policy hash</dt>
          <dd>
            <code>{redactText(manifest.policy_hash)}</code>
          </dd>
        </div>
        <div className="manifest-wide">
          <dt>Evidence</dt>
          <dd>Evidence: {redactText(manifest.evidence_event_ids.join(' · '))}</dd>
        </div>
        <div className="manifest-digest manifest-wide">
          <dt>Manifest SHA-256</dt>
          <dd>
            <code>{redactText(manifest.digest_sha256)}</code>
          </dd>
        </div>
      </dl>
      <div className="manifest-outcomes" aria-label="Regression assertions">
        <strong>Assertions</strong>
        <ManifestAssertion
          label="Attack attempted"
          value={manifest.assertions.attack_attempted}
        />
        <ManifestAssertion label="Attack blocked" value={manifest.assertions.attack_blocked} />
        <ManifestAssertion
          label="Secret exposed"
          passesWhen={false}
          value={manifest.assertions.secret_exposed}
        />
        <ManifestAssertion label="Code fixed" value={manifest.assertions.code_fixed} />
        <ManifestAssertion label="Tests passed" value={manifest.assertions.tests_passed} />
      </div>
      <a
        className="manifest-download"
        download="cutline-regression-manifest.json"
        href="/api/demo/regression-manifest"
      >
        <Download aria-hidden="true" size={15} />
        Download JSON manifest
      </a>
    </article>
  )
}

function IntegrationsPanel({ integrations }: { integrations: DemoState['integrations'] }) {
  return (
    <article className="panel integrations-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Runtime</span>
          <h3>Integration status</h3>
        </div>
      </div>
      <div className="integration-list">
        {Object.entries(integrations).map(([name, integration]) => {
          const status = normalizedIntegrationState(integration)
          return (
            <div className="integration" key={name} title={statusMessage(integration) || undefined}>
              <span>{redactText(integration.provider)}</span>
              <strong className={`integration-state ${status}`}>{status}</strong>
            </div>
          )
        })}
      </div>
    </article>
  )
}

type ActionName = 'incident' | 'policy' | 'replay' | 'reset'

type LifecycleState =
  | 'IDLE'
  | 'RUNNING'
  | 'INCIDENT DETECTED'
  | 'GUARDRAIL PROPOSED'
  | 'REPLAYING'
  | 'PATCH VERIFIED'
  | 'ERROR'

const storySteps = [
  { label: 'Trusted user task', tone: 'trusted' },
  { label: 'Untrusted repository instruction', tone: 'danger' },
  { label: 'Synthetic sensitive-file read', tone: 'danger' },
  { label: 'Attempted external write', tone: 'danger' },
  { label: 'Incident detected', tone: 'danger' },
  { label: 'Guardrail proposed', tone: 'control' },
  { label: 'Human approval', tone: 'control' },
  { label: 'Replay blocks the attack', tone: 'safe' },
  { label: 'Legitimate task still succeeds', tone: 'safe' },
] as const

function lifecycleState(
  state: DemoState,
  loading: ActionName | null,
  error: string | null,
): LifecycleState {
  if (error) return 'ERROR'
  if (loading === 'replay') return 'REPLAYING'
  if (loading) return 'RUNNING'
  if (state.replay_run) return 'PATCH VERIFIED'
  if (state.proposed_policy) return 'GUARDRAIL PROPOSED'
  if (state.vulnerable_run) return 'INCIDENT DETECTED'
  return 'IDLE'
}

function completedStorySteps(state: DemoState, loading: ActionName | null) {
  if (state.replay_run) return storySteps.length
  if (loading === 'replay') return 7
  if (state.proposed_policy) return 6
  if (state.vulnerable_run) return 5
  if (loading) return 1
  return 0
}

function CurrentStatus({
  current,
  state,
  loading,
  selectedProvider,
}: {
  current: LifecycleState
  state: DemoState
  loading: ActionName | null
  selectedProvider: string
}) {
  const completedSteps = completedStorySteps(state, loading)
  const safeProvider = redactText(selectedProvider)
  const descriptions: Record<LifecycleState, string> = {
    IDLE: 'Ready to run one controlled synthetic incident.',
    RUNNING: 'Executing the trusted task and recording every decision.',
    'INCIDENT DETECTED': 'Untrusted instruction reached a secret read and external-write attempt.',
    'GUARDRAIL PROPOSED': 'Review the narrow guardrail, then approve one exact replay.',
    REPLAYING: `Enforcing the approved policy in a fresh ${safeProvider} fixture.`,
    'PATCH VERIFIED': 'Attack blocked. Application fixed. Tests passed.',
    ERROR: 'Demo action failed. Review the error and reset or retry.',
  }

  return (
    <section
      aria-label="Current incident status"
      className={`panel status-board status-${current.toLowerCase().replaceAll(' ', '-')}`}
    >
      <div className="current-status">
        <span className="eyebrow">Current incident status</span>
        <h2>{current}</h2>
        <p>{descriptions[current]}</p>
        <div className="status-provider">
          <span>Replay provider</span>
          <strong>{safeProvider}</strong>
        </div>
      </div>
      <ol aria-label="CUTLINE security story" className="story-list">
        {storySteps.map((step, index) => {
          const progress =
            index < completedSteps ? 'complete' : index === completedSteps ? 'active' : 'pending'
          return (
            <li className={`story-step ${step.tone} ${progress}`} key={step.label}>
              <span>{String(index + 1).padStart(2, '0')}</span>
              <strong>{step.label}</strong>
            </li>
          )
        })}
      </ol>
    </section>
  )
}

const actionMessages: Record<ActionName, { progress: string; complete: string }> = {
  incident: {
    progress: 'Running compromised agent…',
    complete: 'Incident run complete.',
  },
  policy: {
    progress: 'Generating deterministic guardrail…',
    complete: 'Guardrail generated.',
  },
  replay: {
    progress: 'Replaying approved guardrail…',
    complete: 'Replay complete.',
  },
  reset: {
    progress: 'Resetting demo…',
    complete: 'Demo reset.',
  },
}

export default function App() {
  const [state, setState] = useState<DemoState>(emptyState)
  const [loading, setLoading] = useState<ActionName | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [announcement, setAnnouncement] = useState('')
  const [selectedProvider, setSelectedProvider] = useState<ReplayProvider>('local')
  const [evidenceView, setEvidenceView] = useState<'incident' | 'replay'>('replay')

  useEffect(() => {
    let active = true
    api
      .state()
      .then((nextState) => {
        if (active) setState(nextState)
      })
      .catch((err: Error) => {
        if (active) setError(redactText(err.message, 'Unable to load demo state.'))
      })
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (!providerSelectable(state, selectedProvider) && providerReady(state, 'local')) {
      setSelectedProvider('local')
    }
  }, [selectedProvider, state])

  const perform = async (name: ActionName, action: () => Promise<DemoState>) => {
    setLoading(name)
    setError(null)
    setAnnouncement(actionMessages[name].progress)
    try {
      const nextState = await action()
      setState(nextState)
      if (name === 'replay') setEvidenceView('replay')
      if (name === 'incident' || name === 'reset') setEvidenceView('incident')
      if (name === 'reset') setSelectedProvider('local')
      setAnnouncement(actionMessages[name].complete)
    } catch (err) {
      setError(
        redactText(
          err instanceof Error ? err.message : 'Unknown error',
          'Request could not be completed.',
        ),
      )
      setAnnouncement('')
    } finally {
      setLoading(null)
    }
  }

  const replayReady = providerSelectable(state, selectedProvider)
  const currentLifecycle = lifecycleState(state, loading, error)
  const displayedProvider = state.replay_run?.provider ?? selectedProvider

  return (
    <main aria-busy={Boolean(loading)} className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">C</div>
          <div>
            <h1>CUTLINE</h1>
            <span>Counterfactual agent incident response</span>
          </div>
        </div>
        <div className="top-status">
          <span aria-hidden="true" className="live-dot" />
          DEFENSIVE SYNTHETIC DEMO
        </div>
      </header>

      <section className="hero">
        <div>
          <span className="eyebrow">Incident → guardrail → verified replay</span>
          <h2>
            Stop the attack.
            <br />
            Keep the agent useful.
          </h2>
          <p>
            Reconstruct a compromised coding-agent run, select a low-disruption deterministic
            control from curated candidates, and replay the task to prove security without losing
            utility.
          </p>
        </div>
        <div className="actions">
          <button
            className="primary danger-button"
            disabled={Boolean(loading)}
            onClick={() => perform('incident', api.runVulnerable)}
            type="button"
          >
            <Play aria-hidden="true" size={17} />
            {loading === 'incident' ? 'Running…' : 'Run compromised agent'}
          </button>
          <button
            className="primary"
            disabled={Boolean(loading) || !state.vulnerable_run || Boolean(state.replay_run)}
            onClick={() => perform('policy', api.generatePolicy)}
            type="button"
          >
            <ShieldCheck aria-hidden="true" size={17} />
            {loading === 'policy' ? 'Generating…' : 'Generate guardrail'}
          </button>
          <button
            aria-describedby={state.replay_run ? undefined : 'replay-approval'}
            className="primary safe-button"
            disabled={
              Boolean(loading) ||
              !state.proposed_policy ||
              !replayReady ||
              Boolean(state.replay_run)
            }
            onClick={() => {
              const policy = state.proposed_policy
              if (policy) {
                void perform('replay', () => api.replay(policy, selectedProvider))
              }
            }}
            type="button"
          >
            <RefreshCcw aria-hidden="true" size={17} />
            {loading === 'replay' ? 'Replaying…' : 'Approve and replay'}
          </button>
          <button
            aria-label="Reset demo"
            className="secondary"
            disabled={Boolean(loading)}
            onClick={() => perform('reset', api.reset)}
            type="button"
          >
            Reset
          </button>
        </div>
      </section>

      <div
        aria-atomic="true"
        aria-live="polite"
        className={announcement ? 'operation-status' : 'sr-only'}
        role="status"
      >
        {announcement}
      </div>
      {error && (
        <div aria-live="assertive" className="error-banner" role="alert">
          {error}
        </div>
      )}

      <CurrentStatus
        current={currentLifecycle}
        loading={loading}
        selectedProvider={displayedProvider}
        state={state}
      />

      <section aria-label="Before and after outcomes" className="results-grid">
        <RunCard title="Before - monitor mode" run={state.vulnerable_run} />
        <RunCard title="After - enforce mode" run={state.replay_run} />
      </section>

      <CompromisedExecution run={state.vulnerable_run} />

      <section className="main-grid">
        <div className="left-column">
          <AttackPath incident={state.vulnerable_run} replay={state.replay_run} />
          <PolicyPanel
            onProviderChange={setSelectedProvider}
            policy={state.proposed_policy}
            selectedProvider={selectedProvider}
            state={state}
          />
          {state.regression_manifest && (
            <RegressionManifestPanel manifest={state.regression_manifest} />
          )}
        </div>

        <aside className="right-column">
          <EvidencePanel
            incident={state.vulnerable_run}
            onSelect={setEvidenceView}
            replay={state.replay_run}
            selected={evidenceView}
          />
          <IntegrationsPanel integrations={state.integrations} />
        </aside>
      </section>
    </main>
  )
}
