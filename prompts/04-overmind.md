Implement Overmind tracing only after local and Modal paths are stable.

Use current official Overmind documentation. Do not guess package names, imports, decorators, or environment variables.

Trace:

- one entry point per agent run;
- one workflow for the fix-and-verify process;
- tool spans for reading the workspace rule, reading the synthetic secret, attempting the mock upload, writing the code fix, and running tests.

Constraints:

- Overmind must be optional and disabled when its API key is absent.
- The local demo must not fail because tracing is unavailable.
- Secret-bearing tool spans must disable captured inputs/outputs when the SDK supports it.
- Use a stable agent identity.
- Never send the raw synthetic secret as a trace attribute.
- Add an integration status indicator.
- Document one command or action proving vulnerable and replay traces arrived.

Run all local tests and frontend build. State whether a real trace was observed; do not infer it.
