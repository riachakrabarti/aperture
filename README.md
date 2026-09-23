# Aperture runtime and assurance MVP (v0.3)

**v0.3 review fixes.** Strict policy-data validation now rejects malformed configuration before OPA starts. Each ledger is pinned to one policy hash, including legacy v0.2 history; a changed policy requires a fresh data directory. Evidence bundles include an Ed25519-signed manifest authenticating every exported member, and the verifier independently recomputes derived reports. Coverage correlation checks workflow, tool, argument hash and execution identity. See `CHANGES_v0.3.md` for compatibility notes and remaining gaps.

**Assurance:** `python assurance.py` runs the original 27 checks plus 14 release regression groups, including both profiles, malformed configuration, every bundle member, request-ID isolation and abrupt process termination. A passing result is synthetic engineering evidence, not customer validation.

**What changed in v0.2.** (1) Trajectory, egress, approval and budget logic moved out of Python and into policy. `policies/aperture_data.json` is the single source of truth for the tool registry (schemas plus semantic tags such as `source:restricted`, `effect:stage`, `sink:external`) and for the profile policy packs. The gateway passes only the workflow's recorded action history to OPA; it no longer computes `restricted` or `spent` flags. (2) Two deployment profiles run on the same engine, selectable per workflow and switchable in one UI: **Commercial** and **Federal-adjacent**. v0.1 data directories are refused; start v0.2 with a fresh `--data` directory.

## Profiles

| | Commercial | Federal-adjacent |
|---|---|---|
| Restricted/CUI read then external send | Approvable | Approvable, and only to an allowlisted destination |
| Read, stage, send | Approvable | Hard block; an approval cannot override |
| Egress allowlist | None | `partner.example` |
| Maximum approval lifetime | 15 minutes | 5 minutes |
| Evidence mapping | SIEM triage categories (suggested MITRE ATT&CK tactic IDs) | NIST SP 800-53 Rev. 5 control identifiers, **draft, not reviewed by an assessor** |

A profile is bound to a workflow when the workflow is created, so a decision always replays under the profile it was made in. Evidence bundles add `policy_data.json`, `controls.json` (per-profile counts of decisions offered as evidence toward each mapped item) and `control-evidence.csv` (one row per decision per mapped item). A mapped row means the decision is offered as evidence toward that control; it does not mean the control is satisfied.

Federal-adjacent gaps that remain: no GovCloud or Impact Level hosting; Ed25519 signatures via pyca/cryptography without an established FIPS 140-validated module; the control mapping needs review by someone who has taken a system through an ATO.

## Writing a new rule

Rules are data. To add a trajectory rule, add an entry to a profile's `sequence_rules` with a two- or three-step ordered `pattern` of tags and an `overridable` flag. To change what a tool means, change its `tags` (or a profile's `extra_tags`). No Python changes are needed; the assurance test "Trajectory rules are policy data, not code" demonstrates this by retagging one tool in a copy of the data. The configuration validator rejects patterns outside two or three steps before activation. Missing fields, invalid types, unknown pattern tags and missing spend/egress metadata are also rejected. Rego retains its pattern-length fail-closed defense. The workflow history visible to policy is capped by `max_history` (500); at the cap, further actions are denied.


A runnable local engineering pilot combining an MCP tool gateway with an outcome-based assurance suite. Both use the same Open Policy Agent (OPA) Rego policy. The included downstream service performs synthetic business actions and maintains its own persistent ledger.

**This is implemented software with real local HTTP requests, OPA decisions, SQLite state, Ed25519 signatures, and repeatable tests. Business systems and identities are synthetic. It is not a production security deployment or a completed ServiceNow/Salesforce integration.**

## Quick start

Requires Python 3.10+ (tested on Python 3.12), a modern browser, and OPA 1.0.1. A Linux amd64 OPA executable is included. Other platforms use the setup script to download the pinned official release. OPA telemetry is disabled when started by this application.

From this folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python setup.py
python aperture.py
```

Open **http://127.0.0.1:8080**. Open the generated `data/credentials.json` locally and paste the `operator` token into the dashboard. The separate `reviewer` token is required for approvals. Credentials remain in tab memory and are not persisted in browser storage.

Windows: activate with `.venv\Scripts\activate`, use `python` instead of `python3`, and start with `python aperture.py --opa bin/opa.exe`. macOS/Windows setup paths are provided but were not executed in this Linux environment.

The service binds to loopback only. No analytics, external model calls, or automatic SIEM uploads. The app launches OPA on 8181 and a private synthetic tool service on an ephemeral loopback port. Override the app and OPA ports with `--port` and `--opa-port` if necessary. Keep one server process per data directory.

## Eight-minute walkthrough

1. Create a workflow with the default 10,000-cent budget.
2. Execute `crm.read`, then `archive.create` as `agent-a`.
3. Switch to `agent-b`; execute `external.send`. It is denied because the same workflow has accessed a restricted source. Changing the transport session does not clear that state.
4. Select `access.grant` with role `reader`. An unapproved call is denied.
5. Enter the reviewer token and approve the selected action. Execute the exact action. It succeeds. Execute again with the same approval but a new request ID: denied.
6. Execute `spend.commit` for 6,000 cents twice. The second call exceeds the cumulative 10,000-cent cap and is denied.
7. Open Assurance lab and run the suite. It creates isolated fixtures; the production-demo workflow and evidence are unchanged.
8. Open Evidence & replay, verify the signed chain, and export the bundle.

The dashboard is an explicit operator-controlled demo surface. Real MCP callers must use an agent credential and a server-created workflow. The reviewer cannot create workflows or execute demo calls. An agent cannot create workflows, approve actions, or access the dashboard API.

## Test from the command line

No running application is required for the assurance suite:

```bash
python assurance.py --output assurance-report.json
```

The suite launches a telemetry-disabled OPA process on port 8282 and local mock services. It tests the v0.2 profile and policy-as-data behavior (approval overrides, profile isolation, federal egress, non-overridable staged exfiltration, profile approval lifetime, and a data-only rule change), plus trajectory blocking, skipping the archive step, agent handoff, allowed behavior, exact approvals, substitution, replay, expiration, separation of duties, concurrent spending, request idempotency, unknown tools, direct unauthenticated bypass, policy outage, unresolved outcomes, persisted history, signature tampering/truncation, decision replay, a deliberately broken-policy negative control, and actual MCP HTTP session isolation.

For a live two-client MCP demonstration, keep `aperture.py` running and use another terminal:

```bash
python demo.py --output demo-output
python verify_bundle.py demo-output/evidence.zip \
  --trusted-key demo-output/trusted-public-key.txt \
  --checkpoint demo-output/checkpoint.json \
  --opa bin/opa
```

Verification re-evaluates recorded policy inputs without executing tools. Preserve public keys and checkpoints separately in a trusted location. A checkpoint delivered inside its own bundle proves internal consistency, not freshness or the absence of a wholly substituted bundle.

## Implemented architecture

| Component | Implementation |
|---|---|
| Incoming protocol | Bounded JSON-response subset of MCP Streamable HTTP pinned to 2025-11-25; initialize, initialized notification, ping, tools/list, tools/call |
| Client authorization | Random local bearer credentials mapped to fixed operator, reviewer, agent-a, and agent-b identities |
| Workflow authority | Operator creates workflow, agent membership, owner, and budget; transport session is bound to authenticated agent and workflow |
| Policy engine | OPA 1.0.1, Rego v1; no alternative permissive fallback |
| Protected state | SQLite WAL with FULL synchronous writes; one-process serialization across decisions and dispatch |
| Durable execution | Persist signed intent, consumed approval, budget reservation, and unresolved marker before dispatch |
| Unknown outcome | Quarantine workflow; do not auto-retry; reservations remain consumed |
| Downstream | Separate HTTP MCP synthetic service, private credential, persistent ledger, decision-ID deduplication |
| Evidence | Ed25519-signed hash chain, signed checkpoint, policy source, decision inputs, downstream observations |
| Assurance | Isolated fixtures execute the actual gateway/runtime code and inspect downstream effects |
| SIEM | Splunk HEC-shaped NDJSON, explicit HTTPS uploader, sourcetype config, example searches |
| Interface | Local responsive HTML/CSS/JavaScript dashboard; no build step or external assets |

## Policy families (v0.1 description; v0.2 expresses these as data, see above)

1. **Restricted-source trajectory:** after the registered restricted CRM read, external send requires an exact-action approval. Archive creation is not a prerequisite for blocking. This is a conservative workflow restriction, not content-level data lineage.
2. **Exact-action approval:** access grants require a reviewer approval bound to workflow, tool and canonical arguments; maximum 15-minute TTL; consumed once. The UI defaults to five minutes. Workflow initiators and member agents cannot self-approve.
3. **Cumulative budget:** integer-cent spend accumulates within a workflow. Serialization and pre-dispatch reservations prevent concurrent overspend in this single-process pilot.

Unknown tools and unresolved workflows are denied. Approvals cannot override these or the spending cap. Tool semantics and restricted-source classification are trusted registry configuration, not LLM classifications.

## MCP client contract

POST to `/mcp`, using these headers:

```text
Authorization: Bearer <agent-a or agent-b token>
X-Aperture-Workflow: <workflow created by operator>
Content-Type: application/json
MCP-Protocol-Version: 2025-11-25
Mcp-Session-Id: <returned by initialize; omit on initialize>
```

JSON-RPC IDs are session-scoped and preserve string/integer distinctions. Within a session, retrying the same ID and action returns the cached result; changing the action conflicts. For an explicitly durable retry across reconnects, pass the same `params._meta["aperture/idempotency_key"]` (1–128 characters). That key is workflow-scoped and bound to the agent, tool, arguments and approval. Without it, a new session creates a new operation; clients must use the explicit key for reconnect-safe retries. Pass approvals with `params._meta["aperture/approval_id"]`.

This is not a full MCP conformance claim. SSE streams, stdio transport, server-initiated calls, resources/prompts, OAuth discovery, session deletion, and protocol versions newer than 2025-11-25 are not implemented. Claude/Bedrock/Foundry/Salesforce/ServiceNow compatibility has not been tested. Two Python MCP clients are exercised by `demo.py`.

## Evidence and data handling

No model prompts are collected. Canonical structured tool arguments, trusted policy state, identity labels, and results are stored locally in the evidence database and bundle so policy decisions can be reproduced. **Local payload storage is not application-encrypted in this pilot.** Use synthetic data only. The signing key and credentials are created with owner-only file permissions where supported, and are excluded from the delivery package.

The key, database, and OPA reside in the same local trust boundary. A host administrator can compromise them. The hash chain is tamper-evident relative to a separately trusted key/checkpoint; it is not immutable storage or proof of complete capture. The evidence does not replay the model, prove an unobserved action never happened, or confer regulatory certification. Version history is single-policy for this MVP; policy hot reload is not supported. Startup refuses a ledger whose stored pin or historical policy hashes differ from the active policy. Restore the original policy or use a fresh data directory; do not delete the ledger to bypass the check.

## Coverage

The displayed percentage compares independent **synthetic downstream action records** with allowed gateway decisions using execution ID, workflow, tool and arguments hash, counting duplicate executions once. It does not estimate all agent activity in an account. The denominator is zero until a tool action is observed. External systems and uninstrumented paths remain unknown. The backend token prevents direct unauthenticated calls within this local test; it is not a substitute for enterprise network/identity enforcement.

## Splunk integration

The evidence bundle includes `siem.ndjson`. The optional script uploads it to an explicitly provided HTTPS HEC endpoint:

```bash
# Set APERTURE_HEC_TOKEN securely in your environment, without committing it.
python export_splunk.py siem.ndjson \
  --url https://YOUR-SPLUNK:8088/services/collector/event
```

Nothing is uploaded automatically. No live Splunk tenant was available; ingestion and SOC usefulness remain unvalidated. Included `splunk/props.conf` and `splunk/searches.txt` provide the intended JSON extraction and searches. NDJSON export is HEC-shaped, not an OTLP implementation.

## What remains before a customer pilot

- Replace synthetic tools with approved real MCP integrations, trustworthy classifications, credential brokerage, and independent outcome audit sources.
- Integrate real delegated identities; preserve trusted workflow lineage across actual platform handoffs. Different logical workflows are separate by design, so an operator granting a new workflow creates fresh state.
- Enforce network and credential restrictions beyond a private local tool token.
- Implement authenticated OPA access, TLS, key management, encrypted payload retention, least-privilege service isolation, request quotas, and operational access controls.
- Replace global serialization with tested distributed reservations if concurrent throughput is required. Multiple application processes sharing this SQLite database are unsupported.
- Add durable outcome reconciliation and a reviewed recovery workflow for quarantined actions. No UI shortcut clears unresolved state.
- Validate real client transports, policy engine maintenance/version, production latency, high availability, customer SIEM ingestion, and procurement requirements.

No p95-under-20-ms claim, enterprise coverage claim, real incident-prevention claim, external platform compatibility claim, or production-readiness claim is made.

## File guide

- `aperture.py`: gateway, state, signing, tool service, HTTP API.
- `policies/controls.rego`: actual runtime policy (generic rules).
- `policies/aperture_data.json`: tool registry, tags, profile policy packs, evidence mappings.
- `assurance.py`: reproducible runtime/outcome tests.
- `demo.py`: live two-client MCP walkthrough.
- `verify_bundle.py`: independent signature verification and offline OPA replay.
- `web/`: dashboard.
- `assurance-report.json`: captured test results from this build.
- `sample-evidence/`: synthetic sample bundle, replay inputs and public verification material.
- `export_splunk.py`, `splunk/`: optional integration scaffold.

## References

Implementation targets: MCP 2025-11-25 Streamable HTTP (https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), OPA REST API (https://www.openpolicyagent.org/docs/rest-api), OPA telemetry switch (https://www.openpolicyagent.org/docs/cli). OPA is an Apache-2.0 third-party dependency; bundled notices are in `THIRD_PARTY_NOTICES.md` and `bin/OPA_LICENSE.txt`. Source is an engineering prototype delivered for review and adaptation.

## Evidence verification in v0.3

`verify_bundle.py` requires the signed manifest format; older unsigned v0.2 bundles are deliberately rejected. Keep the old verifier for historical exports, or re-export an unchanged-policy v0.2 ledger through v0.3. The verifier emits success only after all requested checks finish. Its report separates bundle integrity, event-chain verification, derived-export consistency, optional policy replay and external-checkpoint verification. Replay is explicitly `not_run` unless `--opa` is supplied. Engine-outage decisions are counted separately as nonreplayable.

A signed downstream export authenticates the bytes captured by Aperture. It does not establish independent source authenticity or complete observation. The verifier's recomputation detects inconsistent reports, not dishonest source data. Policy replay reproduces a decision on the recorded inputs; it does not independently prove those inputs describe every real-world event. The local signing key and host remain trusted.

Policy validation intentionally accepts only the bounded registry schema supported by this pilot (object arguments with string/integer properties). Optional properties are supported; unknown properties are rejected. Adding arbitrary JSON Schema constructs requires extending validation and tests explicitly.
