# Aperture v0.3 build status

Review remediation verified on 2026-09-23 in the local Linux environment.

| Gate | Measured result | Evidence |
|---|---|---|
| Assurance CLI | 41/41 check groups passed | assurance-report.json |
| Malformed policy regression | 16 malformed/duplicate configurations rejected; activation path checked | regression_assurance.py and assurance report |
| Bundle tampering | 38 variants rejected across both profiles, including correctly re-signed but inconsistent derived reports | assurance report |
| Crash recovery | Six abrupt subprocess exits: before intent, before dispatch, after dispatch, for both profiles | assurance report |
| Live demo | Both profiles, two custom HTTP clients, 18 decisions | sample-evidence/demo-results.json |
| Evidence verification | Signed manifest and 33-event chain verified; 18 decisions replayed; derived exports consistent | sample-evidence/verification-result.txt |
| Browser integration | 15/15 checks; assurance passed through UI; no page JS errors; no mobile document overflow at 390 px | browser-qa-report.json and PNG previews |

## Review issues resolved

1. Strict policy-data validation prevents missing hard-deny fields from silently disabling rules.
2. A signed manifest authenticates the complete evidence export; the verifier recomputes derived reports and separates verification results.
3. Ledger policy pins reject policy changes across restart, including historical v0.2 ledgers without an existing pin.
4. Coverage checks full action identity and de-duplicates observations.
5. MCP request IDs are session-scoped; explicit durable retry keys survive reconnects.

## Operational limits

This remains a local synthetic pilot. These results do not establish interoperability with independent MCP implementations, behavior with real enterprise tools, real SIEM ingestion, account-wide coverage, production latency, or regulatory compliance. The federal mappings remain draft. The signer, OPA and observation collector share the trusted local host boundary. Signing observations protects captured bytes, not completeness or truth at their source. The policy is fixed per ledger; multiple policy-version replay is not implemented.

The six crash tests use abrupt process exits, not simulated power failure or disk corruption. SQLite's storage guarantees and a real downstream tool's durability still require environment-specific validation.

## Compatibility

Read CHANGES_v0.3.md before replacing an existing installation. Existing v0.2 ledgers require unchanged policy; old evidence bundles lack the new required manifest. No private keys, bearer credentials or runtime databases are included in this release archive.
