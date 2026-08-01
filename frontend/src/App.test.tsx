import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { api } from './api'
import type { DemoState } from './types'

vi.mock('./api', () => ({
  api: {
    state: vi.fn(),
    reset: vi.fn(),
    runVulnerable: vi.fn(),
    generatePolicy: vi.fn(),
    replay: vi.fn(),
  },
}))

const incidentEvent = {
  event_id: 'evt-incident-upload',
  session_id: 'session-incident',
  parent_event_id: 'evt-incident-read',
  sequence_number: 3,
  actor: 'coding-agent',
  source_type: 'tool',
  source_trust: 'UNTRUSTED',
  data_class: 'SECRET',
  tool_name: 'upload_artifact',
  resource: null,
  destination: 'mock://collector/foreign-tenant',
  action_type: 'EXTERNAL_WRITE',
  arguments_redacted: { payload: '[REDACTED]' },
  policy_decision: 'ALLOW',
  outcome: 'uploaded_to_mock_collector',
  message: 'Synthetic secret reached the in-memory collector.',
  timestamp: '2026-08-01T10:00:00Z',
}

const replayEvent = {
  ...incidentEvent,
  event_id: 'evt-replay-upload',
  session_id: 'session-replay',
  policy_decision: 'DENY',
  outcome: 'blocked',
  message: 'Policy blocked synthetic secret egress.',
}

const replayGraph = {
  nodes: [
    {
      id: 'workspace-rule',
      label: 'Poisoned workspace rule',
      kind: 'instruction',
      status: 'danger',
      event_id: 'evt-replay-rule',
    },
    {
      id: 'secret-read',
      label: 'Synthetic secret read',
      kind: 'data',
      status: 'danger',
      event_id: 'evt-replay-read',
    },
    {
      id: 'external-write',
      label: 'External write blocked',
      kind: 'sink',
      status: 'blocked',
      event_id: 'evt-replay-upload',
    },
  ],
  edges: [],
}

const graph = {
  nodes: [
    {
      id: 'workspace-rule',
      label: 'Poisoned workspace rule',
      kind: 'instruction',
      status: 'danger',
      event_id: 'evt-rule',
    },
    {
      id: 'secret-read',
      label: 'Synthetic secret read',
      kind: 'data',
      status: 'danger',
      event_id: 'evt-read',
    },
    {
      id: 'external-write',
      label: 'External write attempt',
      kind: 'sink',
      status: 'danger',
      event_id: 'evt-incident-upload',
    },
  ],
  edges: [],
}

const policy = {
  id: 'block-secret-egress',
  version: 1,
  policy_hash: 'a'.repeat(64),
  title: 'Block unauthorized secret egress',
  description: 'Deny SECRET external writes outside the session allowlist.',
  effect: 'DENY',
  match: {
    data_class: 'SECRET',
    action_type: 'EXTERNAL_WRITE',
    destination: 'NOT_IN_SESSION_ALLOWLIST',
  },
  disruption_score: 1,
  evidence_event_ids: ['evt-rule', 'evt-read', 'evt-incident-upload'],
  candidates: [
    {
      id: 'disable-agent',
      title: 'Disable the agent',
      effect: 'DENY_ALL',
      disruption_score: 100,
      selected: false,
    },
    {
      id: 'block-secret-egress',
      title: 'Deny secret egress to unauthorized destinations',
      effect: 'DENY',
      disruption_score: 1,
      selected: true,
    },
  ],
  yaml: 'effect: DENY',
}

const incidentRun = {
  session_id: 'session-incident',
  mode: 'monitor',
  provider: 'local',
  status: 'INCIDENT DETECTED',
  secret_exposed: true,
  exfiltration_attempted: true,
  exfiltration_blocked: false,
  code_fixed: true,
  tests_passed: true,
  test_output: '1 passed',
  collector_count: 1,
  events: [incidentEvent],
  graph,
}

const replayRun = {
  ...incidentRun,
  session_id: 'session-replay',
  mode: 'enforce',
  status: 'PATCH VERIFIED',
  secret_exposed: false,
  exfiltration_blocked: true,
  collector_count: 0,
  events: [replayEvent],
  graph: replayGraph,
}

const integrations = {
  local: {
    provider: 'local',
    state: 'ready',
    configured: true,
    last_checked_at: '2026-08-01T10:00:00Z',
    message: 'Local deterministic runner ready.',
  },
  modal: {
    provider: 'modal',
    state: 'unverified',
    configured: false,
    last_checked_at: null,
    message: 'Configure and verify one network-blocked Modal replay first.',
  },
}

const fullState = {
  vulnerable_run: incidentRun,
  proposed_policy: policy,
  replay_run: replayRun,
  regression_manifest: {
    schema_version: 1,
    scenario_id: 'workspace-rule-secret-egress',
    scenario_version: 1,
    source_session_id: 'session-incident',
    source_fixture_id: 'fixture-monitor-001',
    replay_session_id: 'session-replay',
    replay_fixture_id: 'fixture-replay-001',
    policy_id: policy.id,
    policy_version: policy.version,
    policy_hash: policy.policy_hash,
    evidence_event_ids: ['evt-rule', 'evt-read', 'evt-incident-upload', 'evt-replay-upload'],
    assertions: {
      attack_attempted: true,
      attack_blocked: true,
      secret_exposed: false,
      code_fixed: true,
      tests_passed: true,
    },
    digest_sha256: 'b'.repeat(64),
  },
  integrations,
} as unknown as DemoState

const stateWithoutManifest = {
  ...fullState,
  regression_manifest: null,
} as DemoState

const emptyState = {
  vulnerable_run: null,
  proposed_policy: null,
  replay_run: null,
  regression_manifest: null,
  integrations,
} as unknown as DemoState

beforeEach(() => {
  vi.mocked(api.state).mockResolvedValue(stateWithoutManifest)
  vi.mocked(api.reset).mockResolvedValue(emptyState)
  vi.mocked(api.runVulnerable).mockResolvedValue({
    ...emptyState,
    vulnerable_run: incidentRun,
  } as unknown as DemoState)
  vi.mocked(api.generatePolicy).mockResolvedValue(stateWithoutManifest)
  vi.mocked(api.replay).mockResolvedValue(stateWithoutManifest)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('CUTLINE console', () => {
  it('makes the complete security story and idle state explicit', async () => {
    vi.mocked(api.state).mockResolvedValue(emptyState)
    render(<App />)

    const currentStatus = await screen.findByRole('region', {
      name: 'Current incident status',
    })
    expect(within(currentStatus).getByRole('heading', { name: 'IDLE' })).toBeInTheDocument()

    const story = screen.getByRole('list', { name: 'CUTLINE security story' })
    for (const label of [
      'Trusted user task',
      'Untrusted repository instruction',
      'Synthetic sensitive-file read',
      'Attempted external write',
      'Incident detected',
      'Guardrail proposed',
      'Human approval',
      'Replay blocks the attack',
      'Legitimate task still succeeds',
    ]) {
      expect(within(story).getByText(label)).toBeInTheDocument()
    }
  })

  it('shows incident, approval, and verified lifecycle states from backend snapshots', async () => {
    vi.mocked(api.state).mockResolvedValue({
      ...emptyState,
      vulnerable_run: incidentRun,
    } as unknown as DemoState)
    const incident = render(<App />)
    expect(
      within(await screen.findByRole('region', { name: 'Current incident status' })).getByRole(
        'heading',
        { name: 'INCIDENT DETECTED' },
      ),
    ).toBeInTheDocument()
    incident.unmount()

    vi.mocked(api.state).mockResolvedValue({
      ...stateWithoutManifest,
      replay_run: null,
    })
    const approval = render(<App />)
    const awaiting = await screen.findByRole('region', { name: 'Current incident status' })
    expect(
      await within(awaiting).findByRole('heading', { name: 'AWAITING APPROVAL' }),
    ).toBeInTheDocument()
    expect(within(awaiting).getByText('GUARDRAIL PROPOSED')).toBeInTheDocument()
    approval.unmount()

    vi.mocked(api.state).mockResolvedValue(fullState)
    render(<App />)
    expect(
      within(await screen.findByRole('region', { name: 'Current incident status' })).getByRole(
        'heading',
        { name: 'PATCH VERIFIED' },
      ),
    ).toBeInTheDocument()
  })

  it('shows the replay graph as blocked after verification', async () => {
    render(<App />)

    const graphPanel = await screen.findByRole('region', { name: 'Attack path visualization' })
    expect(within(graphPanel).getByText('External write blocked')).toBeInTheDocument()
    expect(within(graphPanel).queryByText('Synthetic canary exposed')).not.toBeInTheDocument()
  })

  it('marks exposed synthetic data as danger and idle outcomes as unknown', async () => {
    const completed = render(<App />)

    expect(await screen.findByLabelText('Synthetic secret exposed: yes')).toHaveClass('danger')
    completed.unmount()

    vi.mocked(api.state).mockResolvedValue(emptyState)
    render(<App />)
    expect(await screen.findAllByLabelText('Synthetic secret exposed: not run')).toHaveLength(2)
    expect(screen.getAllByText('NOT RUN')).toHaveLength(8)
  })

  it('shows compact candidate disruption comparison and exact policy lineage', async () => {
    render(<App />)

    const table = await screen.findByRole('table', { name: 'Candidate disruption comparison' })
    expect(within(table).getByText('Disable the agent')).toBeInTheDocument()
    expect(within(table).getByText('100')).toBeInTheDocument()
    expect(within(table).getByText('Selected')).toBeInTheDocument()
    expect(screen.getByText('Version 1')).toBeInTheDocument()
    expect(screen.getByText('aaaaaaaaaaaa…')).toBeInTheDocument()
  })

  it('keeps Modal unavailable with an explicit reason until status is ready', async () => {
    render(<App />)

    const local = await screen.findByRole('radio', { name: 'Local' })
    const modal = screen.getByRole('radio', { name: 'Modal' })
    expect(local).toBeChecked()
    expect(modal).toBeDisabled()
    expect(
      screen.getByText('Configure and verify one network-blocked Modal replay first.'),
    ).toBeInTheDocument()
  })

  it('does not unlock Modal when canonical integration state is missing', async () => {
    vi.mocked(api.state).mockResolvedValue({
      ...stateWithoutManifest,
      integrations: {
        ...integrations,
        modal: {
          provider: 'modal',
          configured: true,
          last_checked_at: null,
          message: 'Canonical provider state missing.',
          enabled: true,
        },
      },
    } as unknown as DemoState)
    render(<App />)

    expect(await screen.findByRole('radio', { name: 'Modal' })).toBeDisabled()
    expect(screen.getByText('Canonical provider state missing.')).toBeInTheDocument()
  })

  it('allows an explicit verification replay for configured unverified Modal', async () => {
    vi.mocked(api.state).mockResolvedValue({
      ...stateWithoutManifest,
      integrations: {
        ...integrations,
        modal: {
          ...integrations.modal,
          state: 'unverified',
          configured: true,
          message: 'Run one network-blocked replay to verify this provider.',
        },
      },
    } as unknown as DemoState)
    const user = userEvent.setup()
    render(<App />)

    const modal = await screen.findByRole('radio', { name: 'Modal' })
    expect(modal).toBeEnabled()
    await user.click(modal)
    await user.click(screen.getByRole('button', { name: 'Approve and replay' }))

    expect(api.replay).toHaveBeenCalledWith(expect.objectContaining({ id: policy.id }), 'modal')
  })

  it('uses selected ready provider for exact-policy replay', async () => {
    vi.mocked(api.state).mockResolvedValue({
      ...fullState,
      replay_run: null,
      regression_manifest: null,
      integrations: {
        ...integrations,
        modal: {
          ...integrations.modal,
          state: 'ready',
          configured: true,
          message: 'Modal network-blocked replay verified.',
        },
      },
    } as unknown as DemoState)
    const user = userEvent.setup()
    render(<App />)

    await user.click(await screen.findByRole('radio', { name: 'Modal' }))
    await user.click(screen.getByRole('button', { name: 'Approve and replay' }))

    expect(api.replay).toHaveBeenCalledWith(expect.objectContaining({ id: policy.id }), 'modal')
  })

  it('labels completed evidence and lets operator distinguish incident from replay', async () => {
    const user = userEvent.setup()
    render(<App />)

    expect(await screen.findByText('Completed trace')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Replay evidence' })).toBeInTheDocument()
    expect(screen.getByText('evt-replay-upload')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Incident evidence' }))

    expect(screen.getByRole('heading', { name: 'Incident evidence' })).toBeInTheDocument()
    expect(screen.getByText('evt-incident-upload')).toBeInTheDocument()
    expect(screen.queryByText('evt-replay-upload')).not.toBeInTheDocument()
  })

  it('announces progress and completed result', async () => {
    let resolveRun: ((state: DemoState) => void) | undefined
    vi.mocked(api.state).mockResolvedValue(emptyState)
    vi.mocked(api.runVulnerable).mockReturnValue(
      new Promise((resolve) => {
        resolveRun = resolve
      }),
    )
    const user = userEvent.setup()
    render(<App />)

    await user.click(await screen.findByRole('button', { name: 'Run compromised agent' }))
    expect(screen.getByRole('status')).toHaveTextContent('Running compromised agent…')
    expect(
      within(screen.getByRole('region', { name: 'Current incident status' })).getByRole(
        'heading',
        { name: 'RUNNING' },
      ),
    ).toBeInTheDocument()

    await act(async () => {
      resolveRun?.({ ...emptyState, vulnerable_run: incidentRun } as unknown as DemoState)
    })

    expect(screen.getByRole('status')).toHaveTextContent('Incident run complete.')
  })

  it('announces actionable request errors', async () => {
    vi.mocked(api.state).mockResolvedValue(emptyState)
    vi.mocked(api.runVulnerable).mockRejectedValue(new Error('Fixture creation failed.'))
    const user = userEvent.setup()
    render(<App />)

    await user.click(await screen.findByRole('button', { name: 'Run compromised agent' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Fixture creation failed.')
    expect(
      within(screen.getByRole('region', { name: 'Current incident status' })).getByRole(
        'heading',
        { name: 'ERROR' },
      ),
    ).toBeInTheDocument()
  })

  it('shows replaying while approved policy executes', async () => {
    let resolveReplay: ((state: DemoState) => void) | undefined
    vi.mocked(api.replay).mockReturnValue(
      new Promise((resolve) => {
        resolveReplay = resolve
      }),
    )
    const user = userEvent.setup()
    render(<App />)

    await user.click(await screen.findByRole('button', { name: 'Approve and replay' }))
    expect(
      within(screen.getByRole('region', { name: 'Current incident status' })).getByRole(
        'heading',
        { name: 'REPLAYING' },
      ),
    ).toBeInTheDocument()

    await act(async () => {
      resolveReplay?.(fullState)
    })
  })

  it('offers regression manifest only after backend state provides one', async () => {
    vi.mocked(api.state).mockResolvedValue(stateWithoutManifest)
    const firstRender = render(<App />)

    expect(await screen.findByText('Completed trace')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Regression manifest' })).not.toBeInTheDocument()
    firstRender.unmount()

    vi.mocked(api.state).mockResolvedValue(fullState)
    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Regression manifest' })).toBeInTheDocument()
    const download = screen.getByRole('link', { name: 'Download JSON manifest' })
    expect(download).toHaveAttribute('href', '/api/demo/regression-manifest')
    expect(download).toHaveAttribute('download')
    expect(screen.getByText('workspace-rule-secret-egress')).toBeInTheDocument()
    expect(screen.getByText('session-incident')).toBeInTheDocument()
    expect(screen.getByText('session-replay')).toBeInTheDocument()
    expect(screen.getByText('Fresh fixture pair')).toBeInTheDocument()
    expect(screen.getByText('fixture-monitor-001')).toBeInTheDocument()
    expect(screen.getByText('fixture-replay-001')).toBeInTheDocument()
    expect(screen.getByText(policy.policy_hash)).toBeInTheDocument()
    expect(screen.getByText('Attack attempted: yes')).toBeInTheDocument()
    expect(screen.getByText('Secret exposed: no')).toBeInTheDocument()
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument()
  })

  it('redacts a synthetic canary if backend reference text contains it', async () => {
    vi.mocked(api.state).mockResolvedValue({
      ...fullState,
      regression_manifest: {
        ...fullState.regression_manifest,
        source_fixture_id: 'fixture-CUTLINE_CANARY_7F3A',
      },
    } as DemoState)
    render(<App />)

    expect(await screen.findByText('fixture-[REDACTED]')).toBeInTheDocument()
    expect(screen.queryByText(/CUTLINE_CANARY_7F3A/)).not.toBeInTheDocument()
  })
})
