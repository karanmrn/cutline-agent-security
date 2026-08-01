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
  LegacyIntegrationStatus,
  ProposedPolicy,
  RegressionManifest,
  ReplayProvider,
  RunResult,
} from './types'

const emptyState: DemoState = {
  vulnerable_run: null,
  proposed_policy: null,
  replay_run: null,
  regression_manifest: null,
  integrations: {},
}

const syntheticCanaryPattern = /CUTLINE_CANARY_[A-Z0-9]+/g

function redactText(value: string | null | undefined, fallback = '') {
  return value ? value.replace(syntheticCanaryPattern, '[REDACTED]') : fallback
}

type AnyIntegrationStatus = IntegrationStatus | LegacyIntegrationStatus

function normalizedIntegrationState(
  status: AnyIntegrationStatus | undefined,
): IntegrationState {
  if (!status) return 'disabled'
  if ('state' in status && status.state) return status.state
  if (status.error) return 'error'
  return status.enabled && status.configured ? 'ready' : 'disabled'
}

function statusMessage(status: AnyIntegrationStatus | undefined) {
  return redactText(status?.message ?? status?.error)
}

function providerReady(state: DemoState, provider: ReplayProvider) {
  return normalizedIntegrationState(state.integrations[provider]) === 'ready'
}

function Outcome({ label, value }: { label: string; value: boolean }) {
  return (
    <div className="outcome-row">
      <span>{label}</span>
      <strong className={value ? 'yes' : 'no'}>{value ? 'YES' : 'NO'}</strong>
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
        <Outcome label="Synthetic secret exposed" value={Boolean(run?.secret_exposed)} />
        <Outcome label="Exfiltration blocked" value={Boolean(run?.exfiltration_blocked)} />
        <Outcome label="Application fixed" value={Boolean(run?.code_fixed)} />
        <Outcome label="Tests passed" value={Boolean(run?.tests_passed)} />
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

function AttackPath({ run }: { run: RunResult | null }) {
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

  const path = (nodes: GraphNode[]) =>
    nodes.map((node, index) => (
      <div className="path-segment" key={node.id}>
        <NodeCard node={node} />
        {index < nodes.length - 1 && (
          <ChevronRight aria-hidden="true" className="path-arrow" size={22} />
        )}
      </div>
    ))

  return (
    <article className="panel graph-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Evidence graph</span>
          <h3>Two paths. One task.</h3>
        </div>
        <Activity aria-hidden="true" size={20} />
      </div>
      {!run ? (
        <div className="empty">Run compromised agent to reconstruct path.</div>
      ) : (
        <div className="graph-lanes">
          <div className="graph-lane">
            <span className="lane-label danger-text">Harmful path</span>
            <div className="path-row">{path(dangerous)}</div>
          </div>
          <div className="graph-lane">
            <span className="lane-label safe-text">Legitimate path</span>
            <div className="path-row">{path(legitimate)}</div>
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
          return (
            <div className={`provider-option ${selected === id ? 'selected' : ''}`} key={id}>
              <div className="provider-option-line">
                <input
                  checked={selected === id}
                  disabled={!ready}
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
    <article className="panel policy-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Least-disruptive control</span>
          <h3>{redactText(policy?.title, 'No guardrail generated')}</h3>
        </div>
        {policy && <div className="score">Cost {policy.disruption_score}</div>}
      </div>
      {!policy ? (
        <div className="empty">Generate guardrail after incident run.</div>
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
          <ProviderSelector
            onSelect={onProviderChange}
            selected={selectedProvider}
            state={state}
          />
          <p className="approval-note" id="replay-approval">
            Approval binds this exact policy version and hash to one fresh{' '}
            {selectedProvider} replay.
          </p>
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

function ManifestOutcome({ label, value }: { label: string; value: boolean }) {
  return (
    <span className={value ? 'safe-text' : 'danger-text'}>
      {label}: {value ? 'pass' : 'fail'}
    </span>
  )
}

function RegressionManifestPanel({ manifest }: { manifest: RegressionManifest }) {
  return (
    <article className="panel manifest-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Permanent proof</span>
          <h3>Regression manifest</h3>
        </div>
        <strong className="manifest-status">
          <FileCheck2 aria-hidden="true" size={14} />
          {manifest.status}
        </strong>
      </div>
      <dl className="manifest-details">
        <div>
          <dt>Schema</dt>
          <dd>{manifest.schema_version}</dd>
        </div>
        <div>
          <dt>Fixture</dt>
          <dd>{redactText(manifest.fixture_id)}</dd>
        </div>
        <div>
          <dt>Provider</dt>
          <dd>{manifest.replay_provider}</dd>
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
        <div className="manifest-wide">
          <dt>Policy hash</dt>
          <dd>
            <code>{redactText(manifest.policy_hash)}</code>
          </dd>
        </div>
        <div className="manifest-wide">
          <dt>Source evidence</dt>
          <dd>Evidence: {redactText(manifest.source_evidence_event_ids.join(' · '))}</dd>
        </div>
        <div className="manifest-wide">
          <dt>Replay evidence</dt>
          <dd>Evidence: {redactText(manifest.replay_evidence_event_ids.join(' · '))}</dd>
        </div>
        <div className="manifest-digest manifest-wide">
          <dt>Artifact SHA-256</dt>
          <dd>
            <code>{redactText(manifest.artifact_sha256)}</code>
          </dd>
        </div>
      </dl>
      <div className="manifest-outcome-grid">
        <div className="manifest-outcomes" aria-label="Expected regression outcomes">
          <strong>Expected</strong>
          <ManifestOutcome label="Attack blocked" value={manifest.expected.attack_blocked} />
          <ManifestOutcome label="Utility retained" value={manifest.expected.utility_retained} />
          <ManifestOutcome label="Tests passed" value={manifest.expected.tests_passed} />
        </div>
        <div className="manifest-outcomes" aria-label="Actual regression outcomes">
          <strong>Actual</strong>
          <ManifestOutcome label="Attack blocked" value={manifest.actual.attack_blocked} />
          <ManifestOutcome label="Utility retained" value={manifest.actual.utility_retained} />
          <ManifestOutcome label="Tests passed" value={manifest.actual.tests_passed} />
        </div>
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
              <span>{redactText(integration.provider ?? name)}</span>
              <strong className={`integration-state ${status}`}>{status}</strong>
            </div>
          )
        })}
      </div>
    </article>
  )
}

type ActionName = 'incident' | 'policy' | 'replay' | 'reset'

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
    if (!providerReady(state, selectedProvider) && providerReady(state, 'local')) {
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

  const replayReady = providerReady(state, selectedProvider)

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
          <h2>Stop attack. Keep agent useful.</h2>
          <p>
            Reconstruct compromised coding-agent run, generate narrowest deterministic control,
            and replay task to prove security without losing utility.
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
            disabled={Boolean(loading) || !state.vulnerable_run}
            onClick={() => perform('policy', api.generatePolicy)}
            type="button"
          >
            <ShieldCheck aria-hidden="true" size={17} />
            {loading === 'policy' ? 'Generating…' : 'Generate guardrail'}
          </button>
          <button
            aria-describedby="replay-approval"
            className="primary safe-button"
            disabled={Boolean(loading) || !state.proposed_policy || !replayReady}
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

      <section aria-label="Before and after outcomes" className="results-grid">
        <RunCard title="Before - monitor mode" run={state.vulnerable_run} />
        <RunCard title="After - enforce mode" run={state.replay_run} />
      </section>

      <section className="main-grid">
        <div className="left-column">
          <AttackPath run={state.vulnerable_run} />
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
