import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Ban,
  Check,
  ChevronRight,
  CircleAlert,
  Code2,
  Database,
  Play,
  RefreshCcw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { api } from './api'
import type { DemoState, Event, GraphNode, RunResult } from './types'

const emptyState: DemoState = {
  vulnerable_run: null,
  proposed_policy: null,
  replay_run: null,
  integrations: {},
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
          <h3>{run?.status ?? 'Waiting'}</h3>
        </div>
        <span className={`status-dot ${run?.secret_exposed ? 'danger' : run ? 'safe' : ''}`} />
      </div>
      <div className="outcomes">
        <Outcome label="Synthetic secret exposed" value={Boolean(run?.secret_exposed)} />
        <Outcome label="Exfiltration blocked" value={Boolean(run?.exfiltration_blocked)} />
        <Outcome label="Application fixed" value={Boolean(run?.code_fixed)} />
        <Outcome label="Tests passed" value={Boolean(run?.tests_passed)} />
      </div>
      <div className="provider-row">
        <span>Provider</span>
        <strong>{run?.provider ?? '—'}</strong>
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
      <div className="node-icon">{icon}</div>
      <div>
        <strong>{node.label}</strong>
        <span>{node.event_id ?? 'product path'}</span>
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
        {index < nodes.length - 1 && <ChevronRight className="path-arrow" size={22} />}
      </div>
    ))

  return (
    <article className="panel graph-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">Evidence graph</span>
          <h3>Two paths. One task.</h3>
        </div>
        <Activity size={20} />
      </div>
      {!run ? (
        <div className="empty">Run the compromised agent to reconstruct the path.</div>
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
          <strong>{event.tool_name}</strong>
          <code>{event.event_id}</code>
        </div>
        <p>{event.message}</p>
        <div className="tags">
          <span>{event.source_trust}</span>
          <span>{event.data_class}</span>
          <span>{event.action_type}</span>
          <span>{event.policy_decision}</span>
        </div>
      </div>
    </div>
  )
}

export default function App() {
  const [state, setState] = useState<DemoState>(emptyState)
  const [loading, setLoading] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.state().then(setState).catch((err: Error) => setError(err.message))
  }, [])

  const perform = async (name: string, action: () => Promise<DemoState>) => {
    setLoading(name)
    setError(null)
    try {
      setState(await action())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(null)
    }
  }

  const activeTrace = state.replay_run ?? state.vulnerable_run
  const integrations = Object.entries(state.integrations)

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">C</div>
          <div>
            <h1>CUTLINE</h1>
            <span>Counterfactual agent incident response</span>
          </div>
        </div>
        <div className="top-status">
          <span className="live-dot" />
          DEFENSIVE SYNTHETIC DEMO
        </div>
      </header>

      <section className="hero">
        <div>
          <span className="eyebrow">Incident → guardrail → verified replay</span>
          <h2>Stop the attack. Keep the agent useful.</h2>
          <p>
            Reconstruct a compromised coding-agent run, generate the narrowest deterministic
            control, and replay the task to prove security without losing utility.
          </p>
        </div>
        <div className="actions">
          <button
            className="primary danger-button"
            disabled={Boolean(loading)}
            onClick={() => perform('incident', api.runVulnerable)}
          >
            <Play size={17} />
            {loading === 'incident' ? 'Running…' : 'Run compromised agent'}
          </button>
          <button
            className="primary"
            disabled={Boolean(loading) || !state.vulnerable_run}
            onClick={() => perform('policy', api.generatePolicy)}
          >
            <ShieldCheck size={17} />
            {loading === 'policy' ? 'Generating…' : 'Generate guardrail'}
          </button>
          <button
            className="primary safe-button"
            disabled={Boolean(loading) || !state.proposed_policy}
            onClick={() => {
              const policy = state.proposed_policy
              if (policy) {
                void perform('replay', () => api.replay(policy))
              }
            }}
            aria-describedby="replay-approval"
          >
            <RefreshCcw size={17} />
            {loading === 'replay' ? 'Replaying…' : 'Approve and replay'}
          </button>
          <button
            className="secondary"
            disabled={Boolean(loading)}
            onClick={() => perform('reset', api.reset)}
            aria-label="Reset demo"
          >
            Reset
          </button>
        </div>
      </section>

      {error && <div className="error-banner">{error}</div>}

      <section className="results-grid">
        <RunCard title="Before — monitor mode" run={state.vulnerable_run} />
        <RunCard title="After — enforce mode" run={state.replay_run} />
      </section>

      <section className="main-grid">
        <div className="left-column">
          <AttackPath run={state.vulnerable_run} />

          <article className="panel policy-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Least-disruptive control</span>
                <h3>{state.proposed_policy?.title ?? 'No guardrail generated'}</h3>
              </div>
              {state.proposed_policy && (
                <div className="score">Cost {state.proposed_policy.disruption_score}</div>
              )}
            </div>
            {!state.proposed_policy ? (
              <div className="empty">Generate a guardrail after the incident run.</div>
            ) : (
              <>
                <p className="policy-description">{state.proposed_policy.description}</p>
                <div className="evidence-row">
                  <span>Evidence</span>
                  <div>
                    {state.proposed_policy.evidence_event_ids.map((eventId) => (
                      <code key={eventId}>{eventId}</code>
                    ))}
                  </div>
                </div>
                <pre>{state.proposed_policy.yaml}</pre>
                <p className="approval-note" id="replay-approval">
                  Approve and replay authorizes this exact policy version for one fresh local run.
                </p>
              </>
            )}
          </article>
        </div>

        <aside className="right-column">
          <article className="panel timeline-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Live evidence</span>
                <h3>Agent execution trace</h3>
              </div>
              <span className="event-count">{activeTrace?.events.length ?? 0} events</span>
            </div>
            <div className="timeline">
              {activeTrace?.events.length ? (
                activeTrace.events.map((event) => <TimelineEvent event={event} key={event.event_id} />)
              ) : (
                <div className="empty">Execution events will appear here.</div>
              )}
            </div>
          </article>

          <article className="panel integrations-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Runtime</span>
                <h3>Integration status</h3>
              </div>
            </div>
            <div className="integration-list">
              {integrations.map(([name, integration]) => (
                <div className="integration" key={name} title={integration.error ?? undefined}>
                  <span>{name}</span>
                  <strong className={integration.enabled ? 'safe-text' : ''}>
                    {integration.enabled ? 'READY' : 'OPTIONAL'}
                  </strong>
                </div>
              ))}
            </div>
          </article>
        </aside>
      </section>
    </main>
  )
}
