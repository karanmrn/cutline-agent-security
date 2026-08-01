# Three-Minute Demo Script

## 0:00–0:20 — problem

“Agent observability tells us what happened. CUTLINE turns one compromised run into a replay-tested guardrail without disabling the useful task.”

## 0:20–0:55 — compromised run

Click **Run compromised agent**.

Point to:

- untrusted workspace instruction;
- secret read;
- external-write attempt;
- synthetic canary exposure;
- successful code fix and tests.

## 0:55–1:25 — evidence path

“The red path is not an LLM guess. Every statement references captured event IDs.”

Show the chain from untrusted rule to secret read to mock sink.

## 1:25–1:55 — guardrail

Click **Generate guardrail**.

“CUTLINE chooses a narrow deterministic rule: deny secret-classified external writes to destinations not authorized by the task.”

## 1:55–2:35 — replay

Click **Approve and replay**.

Show:

- attack attempted: yes;
- policy decision: deny;
- canary exposed: no;
- application fixed: yes;
- tests passed: yes.

## 2:35–3:00 — close

“CUTLINE converts an incident into a versioned policy and permanent regression fixture. Trace, isolate, patch, verify.”

Stop.

## Optional provider evidence after core demo

Show integration states only after the local proof completes. A ready label is
supporting evidence, never part of the enforcement claim. If any provider is
disabled, unverified, or failed, say so directly and keep the local result as
the source of truth.
