Implement the Modal phase only after the local demo passes.

Read @AGENTS.md and @docs/BUILD_PLAN.md. Use current official Modal documentation. Do not guess APIs.

Goal:

- Add an explicit `provider=modal` replay path that runs the synthetic worker in a fresh Modal Sandbox.
- Configure the replay Sandbox with outbound networking blocked.
- Return the same typed RunResult shape as local execution.
- Keep `provider=local` unchanged and fully tested.

Requirements:

1. Add a small Modal module with one documented setup command and one smoke-test command.
2. The Modal image must include only required Python dependencies and CUTLINE source.
3. Use only generated synthetic fixture files.
4. Capture stdout/stderr and return structured errors.
5. Do not silently claim Modal success or silently relabel local execution as Modal.
6. Add a backend availability endpoint or integration status field.
7. Add tests with the Modal client mocked; separately run one real smoke test when credentials are available.
8. Update README with exact setup, run, troubleshooting, and fallback steps.

Before completion, show evidence of:

- local tests passing;
- frontend build passing;
- real Modal smoke-test command and result, or clearly mark it unverified.
