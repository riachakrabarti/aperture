# Aperture v0.3: Local Setup, Vercel Guidance, and Demo Walkthrough

This guide accompanies `Aperture_Runtime_Assurance_MVP_v0.3.zip`.

**Start locally.** This release is a working local engineering pilot with synthetic business actions. It is not a completed ServiceNow/Salesforce integration or a production security deployment. The complete application cannot be deployed unchanged to Vercel.

## 1. What you need

- The v0.3 ZIP, extracted on your computer.
- Python 3.10 or newer. The release was tested with Python 3.12 on Linux.
- A modern browser and Terminal.
- Internet access for installing the Python dependency and, on a Mac, downloading OPA.

No AI model API key, customer tenant, or paid cloud account is required for the local demo. OPA is the Open Policy Agent engine that evaluates the rules. The app starts it automatically; telemetry is disabled.

macOS setup is provided but was not independently executed during release validation. Windows startup notes appear below; the complete assurance tooling was validated on Linux, not Windows.

## 2. Local setup: macOS or Linux

### Step 1: Extract the ZIP

Extract `Aperture_Runtime_Assurance_MVP_v0.3.zip`. Find the inner `aperture_mvp` folder containing `aperture.py`, `setup.py`, and `requirements.txt`.

Use a fresh extracted folder for your first run. Do not copy an older installation's `data` folder into it unless you intend to preserve that installation and its unchanged policy.

### Step 2: Open Terminal in the application folder

On a Mac, type `cd ` (including the space), drag the `aperture_mvp` folder into Terminal, and press Enter. Alternatively, use your actual path:

```bash
cd "/your/path/to/aperture_mvp"
```

Confirm the folder contents:

```bash
ls
```

You should see `aperture.py`, `assurance.py`, `setup.py`, `requirements.txt`, `policies`, and `web`.

### Step 3: Check Python

```bash
python3 --version
```

If Python is missing or older than 3.10, install a supported Python version from https://www.python.org/downloads/ and reopen Terminal. Python 3.12 matches the tested release environment.

### Step 4: Create an isolated environment and install dependencies

Run each command separately. Stop and inspect the error if any command fails.

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
python -m pip install -r requirements.txt
```

```bash
python setup.py
```

The setup script verifies the included Linux amd64 OPA binary or downloads the pinned OPA 1.0.1 release for your platform. On a Mac, this replaces the included Linux binary with a Mac-compatible executable.

### Step 5: Start the application

```bash
python aperture.py
```

Leave this Terminal window open. You should see:

```text
Aperture synthetic pilot: http://127.0.0.1:8080
```

Open http://127.0.0.1:8080 in your browser. Do not open `web/index.html` directly: the dashboard needs the running backend.

### Step 6: Connect to the dashboard

Startup creates `data/credentials.json` inside `aperture_mvp`. Open it locally in a text editor. On a Mac, you can use a second Terminal window in the same application folder:

```bash
open -a TextEdit data/credentials.json
```

| Credential | Use |
|---|---|
| `operator` | Connect to the dashboard, create workflows, and exercise demo actions |
| `reviewer` | Approve restricted actions |
| `agent-a` and `agent-b` | Authenticate programmatic MCP clients |

Copy the `token` value inside the `operator` object, without quotation marks. Paste it into the dashboard's operator-token field and click **Open workspace**. Keep the reviewer token available for the approval demonstration.

Tokens remain in the browser tab's memory. Reloading the page may require reconnecting. Keep credentials and the contents of `data/` private.

## 3. Demonstrate the controls

### Commercial workflow

1. Select **Commercial**.
2. Create a workflow with the default 10,000-cent budget.
3. Select `agent-a`, choose `crm.read`, and execute with arguments `{}`. It should succeed.
4. Execute `archive.create` with `{}`. It should succeed.
5. Switch to `agent-b`, choose `external.send`, and use:

```json
{"destination":"outside.example"}
```

6. Execute the send. It should be blocked because the workflow has already accessed restricted data.
7. Enter the reviewer token and approve that exact send. Execute it again with the resulting approval. It should succeed under the commercial policy.

### Federal-adjacent workflow

1. Select **Federal-adjacent** and create a new workflow. Changing the displayed profile does not change an existing workflow's policy profile.
2. Execute `crm.read`, followed by `archive.create`.
3. Select `external.send` with:

```json
{"destination":"partner.example"}
```

4. Execute it. The staged-exfiltration rule should block it.
5. Approve the exact action and execute again. It should remain blocked: that federal trajectory rule cannot be overridden.

These actions use synthetic records and tools. No real CRM records are read and no actual external transmission occurs. The federal profile is experimental; its control mappings do not establish compliance or authorization.

## 4. Run assurance tests

### Through the dashboard

Open **Assurance lab** and run the suite. The expected result for the unchanged v0.3 package is **41 of 41 checks passed**. Tests use isolated temporary fixtures rather than the workflow you created in the dashboard.

### Through Terminal

Open a second Terminal, change to `aperture_mvp`, and activate the environment:

```bash
source .venv/bin/activate
python assurance.py --output assurance-report.json
```

The main app does not need to be running for this command. The suite starts its own OPA process and synthetic services. Do not run the CLI suite and dashboard suite concurrently; their test ports can conflict.

The 41 checks include malformed policy configuration, evidence tampering, approvals, spending limits, session isolation, policy-version consistency, and six abrupt-process-exit scenarios across the two profiles. The recorded Linux release results also include 15 passing browser checks. These are engineering tests, not customer-production validation.

## 5. Generate and verify an evidence bundle

Keep `python aperture.py` running on its default port. In the second Terminal, with the environment activated, run:

```bash
python demo.py --output demo-output
```

This runs scripted commercial and federal scenarios and writes evidence to `demo-output`.

Verify the bundle:

```bash
python verify_bundle.py demo-output/evidence.zip \
  --trusted-key demo-output/trusted-public-key.txt \
  --checkpoint demo-output/checkpoint.json \
  --opa bin/opa
```

Look for these fields:

```json
{
  "bundle_integrity": "verified",
  "derived_exports": "consistent",
  "external_checkpoint": "verified",
  "policy_replay": "verified"
}
```

Event counts depend on previous actions in the installation. The packaged clean demonstration contains 33 signed events and 18 replayed decisions. Replay reevaluates recorded policy inputs without executing the tools again.

For a meaningful audit trust boundary, retain the trusted public key and checkpoint separately from the exported bundle. Signing proves integrity of captured bytes; it does not prove that unobserved activity never occurred.

## 6. Stop, restart, and troubleshoot

Stop the server with **Control+C** in its Terminal window. Restart from `aperture_mvp` with:

```bash
source .venv/bin/activate
python aperture.py
```

Your workflows, credentials, signing key, and history remain in `data/`. Use only one application process per data directory.

| Issue | What to do |
|---|---|
| `python3` not found | Install Python, reopen Terminal, and check `python3 --version`. |
| `No module named cryptography` | Activate `.venv`, then rerun `python -m pip install -r requirements.txt`. |
| Wrong executable format for OPA | Run `python setup.py` on the computer where you will run the app. Do not reuse another platform's OPA executable. |
| OPA download/checksum failure | Check network access to the official GitHub release; preserve checksum verification and inspect the error. |
| Browser cannot connect | Confirm the server is still running and use the exact URL printed by it. |
| Invalid credential | Use the `operator` token from this installation's generated `data/credentials.json`. |
| Port already in use | Stop the previous instance, or use the alternate-port command below. |
| Policy hash differs from ledger | Restore the original policy or intentionally start a separate data directory. Do not delete history to bypass the check. |

Alternate ports:

```bash
python aperture.py --port 8081 --opa-port 8182
```

Then open http://127.0.0.1:8081. For the scripted demo on that port:

```bash
python demo.py --url http://127.0.0.1:8081 --output demo-output
```

To intentionally start a separate installation state:

```bash
python aperture.py --data data-new
```

Use credentials from `data-new/credentials.json`. The scripted demo must then receive `--credentials data-new/credentials.json`.

### Windows startup notes

In Command Prompt, change to the extracted `aperture_mvp` directory, then run:

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python setup.py
python aperture.py --opa bin/opa.exe
```

Open the same browser URL and credentials file described above. Windows startup is provided as an unverified platform path. Some regression/replay helpers still assume the Unix `bin/opa` filename, so the full Windows assurance suite needs portability work; do not assume it reproduces the Linux 41/41 result unchanged.

## 7. Vercel: what is and is not supported

**The complete v0.3 package is not Vercel-ready.** The repository deploys only a static showcase to Vercel: `vercel.json` sets the output directory to `site/` with no framework or build step, and `.vercelignore` uploads nothing but `site/` and `vercel.json`, so Vercel does not treat the project as a Python app. When the screenshots or `sample-evidence/` change, copy the updated files into `site/img/` and `site/evidence/`.

Vercel's Python runtime runs supported applications as Functions. Its Functions filesystem is read-only except for temporary scratch space. Aperture currently needs durable local SQLite storage, a signing key, a continuously running application process, and a local OPA service. Moving the SQLite database into temporary storage would not preserve the intended durability guarantees.

Official documentation checked September 23, 2026:

- Python runtime: https://vercel.com/docs/functions/runtimes/python
- Function runtimes and filesystem support: https://vercel.com/docs/functions/runtimes

### Engineering path for a hosted version

The following is a proposed implementation sequence, not deployment instructions for functionality already included:

1. Run the Python backend and OPA on a persistent server or container host.
2. Attach protected persistent storage for the database and signing key; retain single-instance execution until concurrency is redesigned.
3. Add HTTPS, hosted-domain configuration, and remote-access authentication.
4. Update the current loopback-only Host/Origin checks with explicit allowed domains.
5. Host the dashboard assets on Vercel and route API requests to the backend, with an explicitly configured origin/proxy design.
6. Keep credentials, signing keys, and runtime databases out of source control and static assets.
7. Rerun assurance, replay, restart, and browser tests against the hosted deployment before sharing it.

Uploading only `web/` would not produce a working MVP: its dashboard requires backend API endpoints. For an immediate demonstration, run locally and share your screen.

## 8. Plain-English verbal walkthrough

Use this short script while showing the dashboard:

**Introduce the product:**

> “Aperture checks what an AI agent is about to do, taking account of earlier actions in the same workflow. This demo uses synthetic tools so we can safely test the controls.”

**Show the sequence:**

> “The first agent reads a restricted record and creates an archive. A second agent now tries to send something outside. Aperture remembers the workflow history and blocks that next action.”

**Show commercial approval:**

> “A separate reviewer can approve this exact action under the commercial rules. Changing the arguments or reusing a consumed approval does not provide unrestricted permission.”

**Show the federal profile:**

> “In this profile, the read-then-archive-then-send sequence is a hard block. Even an approval cannot override that rule. This demonstrates different policy behavior, not a compliance certification.”

**Show assurance:**

> “The assurance suite tries allowed and prohibited actions, including crashes and tampering. It checks whether the synthetic downstream effects match the expected controls.”

**Show evidence:**

> “We can export signed evidence and replay the policy decisions. That lets someone check that the exported files have not changed and that the recorded decisions reproduce under the recorded policy.”

**Close accurately:**

> “This is a tested local prototype. The next milestone is validating the same controls with real tools, independent clients, and a customer's environment.”
