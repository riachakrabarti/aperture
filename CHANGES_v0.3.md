# Aperture v0.3 — review remediation

## Changes

- Strict policy-data validation before activation and when constructing a policy object. Missing `overridable`, malformed patterns/types, unknown tag references and missing spend/egress metadata cannot silently remove a control. Duplicate JSON keys are rejected.
- Single-policy ledger enforcement. Unchanged v0.2 ledgers are adopted after checking historical hashes; mixed/changed policies are refused. Startup failure cleans up the OPA and downstream processes.
- Signed evidence manifest covering the exact bundle file set. Missing, extra, duplicate and altered members are rejected. Derived control JSON/CSV, SIEM export and coverage counts are independently recomputed. Policy hashes are checked even without replay.
- Coverage binds execution ID, workflow, tool and arguments; duplicate observations cannot inflate matched counts.
- JSON-RPC IDs are scoped to sessions, with type preservation. Explicit `aperture/idempotency_key` supports durable retries across reconnects.
- Assurance is integrated into both the CLI and dashboard. New tests include abrupt subprocess termination before intent, before dispatch and after downstream execution for both profiles.

## Compatibility

Use a fresh directory when intentionally changing policy. Existing v0.2 directories work only with the same policy source/data; v0.1 remains unsupported. The v0.3 verifier intentionally rejects old bundles without a signed manifest. Re-export unchanged-policy ledgers or retain the historical verifier. Clients needing reconnect-safe retries must supply the explicit idempotency key.

## Scope retained

Synthetic downstream only. No independently implemented MCP-client conformance run, customer SIEM validation, account-wide bypass visibility, production load/latency claim, GovCloud deployment or certification. Crash tests terminate the application process; they do not simulate disk corruption, power failure, or an external tool's own durability guarantees. Observations and signatures remain within the trusted local host boundary.

## Reproduce

1. `python setup.py`
2. `python assurance.py`
3. `python validate_build.py` (live demo and manifest/replay verification)
4. Optional UI integration: `python validate_build.py --browser` with Playwright and Chromium available.

See `assurance-report.json`, `browser-qa-report.json`, and `sample-evidence/verification-result.txt` for this build's measured results.
