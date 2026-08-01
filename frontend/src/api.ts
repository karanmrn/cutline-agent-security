import type { DemoState, ProposedPolicy } from './types'

async function request(
  path: string,
  method: 'GET' | 'POST' = 'GET',
  body?: unknown,
): Promise<DemoState> {
  const response = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const responseBody = await response.json().catch(() => ({}))
  if (!response.ok) {
    const message =
      typeof responseBody.detail === 'string'
        ? responseBody.detail
        : `Request failed: ${response.status}`
    throw new Error(message)
  }
  return responseBody as DemoState
}

export const api = {
  state: () => request('/api/state'),
  reset: () => request('/api/demo/reset', 'POST'),
  runVulnerable: () => request('/api/demo/run-vulnerable', 'POST'),
  generatePolicy: () => request('/api/demo/generate-policy', 'POST'),
  replay: (policy: ProposedPolicy) =>
    request('/api/demo/replay', 'POST', {
      approved: true,
      policy_id: policy.id,
      policy_version: policy.version,
    }),
}
