# Third-party components

## Open Policy Agent

Version: 1.0.1. Source: https://github.com/open-policy-agent/opa/tree/v1.0.1

The bundled unmodified Linux amd64 static executable was obtained from the official OPA download endpoint. Its SHA-256 is recorded in `bin/opa.sha256`. License: Apache License 2.0, reproduced in `bin/OPA_LICENSE.txt`. OPA is a project of the Cloud Native Computing Foundation; no affiliation or endorsement is implied.

## Python cryptography

Version pinned for this build: 46.0.0. Installed by the user through `requirements.txt`; not bundled. Source and licensing: https://github.com/pyca/cryptography

## Browser sandbox (site/demo)

The hosted sandbox vendors two unmodified browser libraries in `site/demo/vendor/`:

- `@open-policy-agent/opa-wasm` 1.10.0 (`opa-wasm-browser.esm.js`, source-map comment removed). License: Apache License 2.0, in `site/demo/vendor/OPA_WASM_LICENSE.txt`. Source: https://github.com/open-policy-agent/npm-opa-wasm
- `@noble/ed25519` 3.2.0 (`noble-ed25519.js`). License: MIT, in `site/demo/vendor/NOBLE_ED25519_LICENSE.txt`. Source: https://github.com/paulmillr/noble-ed25519

`site/demo/policy/policy.wasm` is `policies/controls.rego` compiled by OPA 1.0.1 (`python tools/build_site_demo.py`).

The dashboard uses system fonts and no third-party scripts, remote fonts, or external imagery.
