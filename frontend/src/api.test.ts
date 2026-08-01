import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'
import type { ProposedPolicy } from './types'

describe('replay API contract', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('binds replay to exact policy hash and selected provider', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulnerable_run: null,
        proposed_policy: null,
        replay_run: null,
        regression_manifest: null,
        integrations: {},
      }),
    })
    vi.stubGlobal('fetch', fetchMock)
    const policy = {
      id: 'block-secret-egress',
      version: 1,
      policy_hash: 'a'.repeat(64),
      title: 'Block unauthorized secret egress',
      description: 'Deny narrow synthetic secret egress.',
      effect: 'DENY',
      match: {
        data_class: 'SECRET',
        action_type: 'EXTERNAL_WRITE',
        destination: 'NOT_IN_SESSION_ALLOWLIST',
      },
      disruption_score: 1,
      evidence_event_ids: ['evt-rule', 'evt-read', 'evt-upload'],
      candidates: [],
      yaml: 'effect: DENY',
    } as ProposedPolicy & { policy_hash: string }

    await api.replay(policy, 'modal')

    const [, init] = fetchMock.mock.calls[0]
    expect(JSON.parse(String(init.body))).toEqual({
      approved: true,
      policy_id: 'block-secret-egress',
      policy_version: 1,
      policy_hash: 'a'.repeat(64),
      provider: 'modal',
    })
  })
})
