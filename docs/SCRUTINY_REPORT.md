# Agent Canary scrutiny report

**Date:** 2026-08-05  
**Scope:** `C:\code\agent-canary` critical path (plant → trigger → persist → seal → CLI → dashboard data)  
**Verdict:** Real tool after remediation. Core paths are exercised by shipped APIs and tests; one Major fidelity bug and one Major alert-wiring gap were found and fixed in-tree.

## Recon summary

| Check | Result |
|--------|--------|
| Full pytest | **51 passed** (captured `{SCRATCH}/scrutiny-pytest.log`) |
| Grep theater/TODO | `{SCRATCH}/scrutiny-grep.log` — no hollow `...` stubs on critical path; “fake” hits are intentional honeypot templates |
| CLI twice | `{SCRATCH}/scrutiny-cli.log` — `init` + plant file/api + triggers JSON + `forensic verify` OK ×2 |
| Optional extras | `mcp` + `coincurve` present in this environment; Nostr **relay publish** not required for pass |

## Counts

| Severity | Count | Status |
|----------|------:|--------|
| Critical | 0 | — |
| Major | 2 found | **Fixed** |
| Minor | 3 | Deferred / documented |

## Findings

### M1 — FIXED: `get_triggers` dropped forensic fields

- **Evidence (tool):** Probe showed `preceding_tool_calls=[]` and `classification` reset to defaults after log→reload despite correct `event_json` on write.
- **Cite:** `src/agent_canary/registry.py` `get_triggers` (pre-fix omitted `Classification`, `ToolCall` list, session/system prompt fields).
- **Remediation:** Full rehydrate via `_event_from_dict`; tests in `tests/test_registry.py::test_trigger_forensic_roundtrip` assert tool calls + classification + seal.

### M2 — FIXED: Alerts never fired on real triggers

- **Evidence (read):** `dispatch_alerts` only called from `alert test`; `watch` / `serve-mcp` / `serve-api` / `run` passed no `callback` / `on_trigger`.
- **Cite:** `cli.py` pre-fix `FileWatcher(reg)` without callback; MCP/API servers without `on_trigger`.
- **Remediation:** `fire_alerts()` in `alerts.py`; CLI wires `_alert_callback(reg)` for watch/serve-mcp/serve-api/run. Test: `tests/test_alerts_fire.py`.

### m1 — Deferred: OS file-open detection is best-effort

- **Evidence:** Watchdog `on_opened` / `on_accessed` are platform-dependent; README already documents manual `check_file_access` for MCP wrappers.
- **Why deferred:** Not a fake path; integration uses `check_file_access` (shipped). Hardening FS backends is product scope.

### m2 — Deferred: Live Nostr relay publish not gate-tested

- **Evidence:** Unit tests cover BIP-340 seal + NIP-01 sign/verify; client publish needs network relays.
- **Why deferred:** Plan Non-goal; crypto path is not a no-op (tamper tests fail signatures).

### m3 — Deferred: `check_file_access` does not itself call `fire_alerts`

- **Evidence:** Manual check logs to registry only; CLI watch uses watcher callback.
- **Why deferred:** Embedders can call `fire_alerts` after check; not a silent failure of seal/log.

## What is proven real

1. **Plant + multi-vector trigger:** File plant + registry API plant + trigger via `check_file_access` and Starlette decoy; forensic args and chain link seq/prev asserted (`test_file_and_api_planted_trigger_forensics`).
2. **Forensic integrity:** Multi-link seal; content tamper and prev_hash break fail verify; clean chain OK (`tests/test_forensic_chain.py`).
3. **CLI:** `python -m agent_canary` init/list/triggers/forensic verify against temp root; canary + trigger IDs appear in JSON (run twice).
4. **Dashboard data:** Helpers/HTTP return live registry IDs (not hard-coded demo canary strings).

## Grep residual notes

- “Fake” in `templates.py` / README = honeypot content (correct product language).
- `test:00000000` in `alert test` = intentional synthetic event for connectivity.
- Bare `pass` on `CancelledError` / optional `chmod` = intentional, not stub modules.

## Remediations applied (this scrutiny)

1. Registry full event rehydration.
2. Stronger forensic roundtrip + multi-vector integration tests.
3. Alert fire path for CLI services + unit test.

## Residual Critical/Major on plant/trigger/persist/seal/CLI

**Zero.**
