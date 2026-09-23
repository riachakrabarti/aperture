"""Bounded Aperture pilot. Customer-hosted demo, synthetic tools only."""
import argparse
import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from policy_validation import parse_config

ROOT = Path(__file__).resolve().parent
PROTOCOL = "2025-11-25"
VERSION = "0.3.0"
SCHEMA_VERSION = 2
POLICY_REGO = ROOT / "policies/controls.rego"
POLICY_DATA = ROOT / "policies/aperture_data.json"
MAX_BODY = 128 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def uid():
    return str(uuid.uuid4())


class Fault(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def http_json(url, value=None, headers=None, timeout=5):
    req = urllib.request.Request(url, data=canonical(value) if value is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        return json.loads(data) if data else {}


def load_config(path=POLICY_DATA):
    return parse_config(Path(path).read_text())


CONFIG = load_config()
TOOLS = [{"name": n, "description": t["description"], "inputSchema": t["inputSchema"]} for n, t in CONFIG["tools"].items()]
ALLOWED = [t["name"] for t in TOOLS]
PROFILES = list(CONFIG["profiles"])


def validate_args(tool, args):
    """Structural validation only, from the registry schema. Semantics are decided by policy."""
    if not isinstance(args, dict):
        raise Fault(400, "arguments must be an object")
    schema = CONFIG["tools"].get(tool, {}).get("inputSchema")
    if schema is None:
        return  # OPA handles unknown tools with a signed deny decision.
    if not set(schema.get("required", [])) <= set(args) or not set(args) <= set(schema["properties"]):
        raise Fault(400, "arguments do not match the registered tool schema")
    for k, v in args.items():
        spec = schema["properties"][k]
        if spec.get("type") == "integer":
            lo, hi = spec.get("minimum", 1), spec.get("maximum", 1000000)
            if type(v) is not int or not lo <= v <= hi:
                raise Fault(400, f"{k} must be an integer from {lo} to {hi}")
        elif not isinstance(v, str) or not 1 <= len(v) <= 256:
            raise Fault(400, "text arguments must contain 1 to 256 characters")


def policy_hash(rego_text, data_text):
    """One hash over the Rego source and the policy data, so replay can pin both."""
    return digest({"rego": rego_text, "data": json.loads(data_text)})


def fallback_evidence(profile, reason):
    """Evidence mapping for decisions the engine could not make (fail-closed path)."""
    p = CONFIG["profiles"].get(profile, {}).get("evidence", {})
    return {"profile": profile, "framework": p.get("framework", "none"),
            "controls": sorted(set(p.get("baseline", [])) | set(p.get("by_reason", {}).get(reason, []))), "engine": "fallback"}


class Policy:
    def __init__(self, url, source=None, data_text=None):
        self.url = url.rstrip("/")
        self.source = source or POLICY_REGO.read_text()
        self.data_text = data_text or POLICY_DATA.read_text()
        parse_config(self.data_text)
        self.hash = policy_hash(self.source, self.data_text)

    def query(self, rule, value, timeout=2):
        data = http_json(self.url + "/v1/data/aperture/" + rule, {"input": value}, timeout=timeout)
        if "result" not in data:
            raise RuntimeError("OPA returned no result for " + rule)
        return data["result"]

    def evaluate(self, value):
        r = self.query("decision", value)
        if not isinstance(r, dict) or type(r.get("allow")) is not bool or not isinstance(r.get("reasons"), list):
            raise RuntimeError("OPA returned an invalid decision")
        return r


class Ledger:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        keyfile = self.folder / "signing.key"
        if keyfile.exists():
            self.key = Ed25519PrivateKey.from_private_bytes(keyfile.read_bytes())
        else:
            self.key = Ed25519PrivateKey.generate()
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(self.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        self.public = base64.b64encode(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.db = sqlite3.connect(str(self.folder / "aperture.db"), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS workflows(id TEXT PRIMARY KEY, owner TEXT, agents TEXT, state TEXT, budget INTEGER, profile TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS history(workflow TEXT, seq INTEGER, decision_id TEXT, tool TEXT, args TEXT, PRIMARY KEY(workflow, seq));
        CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, workflow TEXT, fingerprint TEXT, approver TEXT, expires REAL, used INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, body TEXT, hash TEXT, signature TEXT);
        CREATE TABLE IF NOT EXISTS requests(workflow TEXT, request_id TEXT, fingerprint TEXT, result TEXT, PRIMARY KEY(workflow,request_id));
        CREATE TABLE IF NOT EXISTS downstream(id TEXT PRIMARY KEY, workflow TEXT, decision_id TEXT, tool TEXT, args TEXT, result TEXT);
        ''')
        columns = {r["name"] for r in self.db.execute("PRAGMA table_info(workflows)")}
        if "profile" not in columns:
            raise RuntimeError("This data directory was created by Aperture v0.1. Start v0.2 with a fresh --data directory.")
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
        self.db.commit()
        self.lock = threading.RLock()

    def pin_policy(self, expected):
        """One policy version per ledger, including legacy ledgers without a pin."""
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                pinned = self.db.execute("SELECT value FROM meta WHERE key='policy_hash'").fetchone()
                hashes = {e['body']['policy_hash'] for e in self.events() if 'policy_hash' in e['body']}
                if (pinned and pinned['value'] != expected) or hashes - {expected}:
                    raise ValueError("Policy hash differs from ledger: restore the original policy or use a fresh data directory; mixed policy history is unsupported")
                self.db.execute("INSERT OR IGNORE INTO meta VALUES('policy_hash', ?)", (expected,))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise

    def append(self, body):
        prev = self.db.execute("SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        body = {**body, "seq": prev["seq"] + 1 if prev else 1, "previous_hash": prev["hash"] if prev else "0" * 64,
                "timestamp_ns": time.time_ns()}
        hashed = digest(body)
        sig = base64.b64encode(self.key.sign(bytes.fromhex(hashed))).decode()
        self.db.execute("INSERT INTO events VALUES(?,?,?,?)", (body["seq"], canonical(body).decode(), hashed, sig))
        return {"body": body, "hash": hashed, "signature": sig}

    def events(self):
        return [{"body": json.loads(r["body"]), "hash": r["hash"], "signature": r["signature"]}
                for r in self.db.execute("SELECT * FROM events ORDER BY seq")]

    def checkpoint(self):
        events = self.events()
        body = {"count": len(events), "head": events[-1]["hash"] if events else "0" * 64, "public_key": self.public}
        return {"body": body, "signature": base64.b64encode(self.key.sign(canonical(body))).decode()}


def verify(events, checkpoint, trusted_public_key):
    """A separately retained checkpoint/key is needed to detect wholesale replacement."""
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_public_key))
    pub.verify(base64.b64decode(checkpoint["signature"]), canonical(checkpoint["body"]))
    if checkpoint["body"]["public_key"] != trusted_public_key:
        raise ValueError("untrusted checkpoint key")
    previous = "0" * 64
    for i, e in enumerate(events, 1):
        b = e["body"]
        if b["seq"] != i or b["previous_hash"] != previous or digest(b) != e["hash"]:
            raise ValueError("event chain mismatch")
        pub.verify(base64.b64decode(e["signature"]), bytes.fromhex(e["hash"]))
        previous = e["hash"]
    if checkpoint["body"]["count"] != len(events) or checkpoint["body"]["head"] != previous:
        raise ValueError("checkpoint mismatch (missing or extra events)")
    return {"valid": True, "events": len(events), "head": previous}


class Downstream:
    """Independent HTTP mock tool server. Only the proxy holds the bearer token."""
    def __init__(self, folder):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(Path(folder) / "tools.db"), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, workflow TEXT, decision_id TEXT, tool TEXT, args TEXT, result TEXT)")
        self.db.commit()
        self.fail_next = False  # Test-only injection, not remotely configurable.
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                if self.path != "/mcp":
                    self.send_error(404); return
                if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + outer.token):
                    self.send_error(401); return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= MAX_BODY: raise ValueError("size")
                    req = json.loads(self.rfile.read(size))
                    method = req.get("method")
                    if method == "initialize":
                        result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}}, "serverInfo": {"name": "aperture-synthetic-tools", "version": VERSION}}
                    elif method == "tools/list": result = {"tools": TOOLS}
                    elif method == "tools/call":
                        with outer.lock:
                            if outer.fail_next:
                                outer.fail_next = False
                                self.send_error(503); return
                            p = req["params"]
                            tool, args = p["name"], p.get("arguments", {})
                            validate_args(tool, args)
                            if tool not in ALLOWED: raise ValueError("unknown tool")
                            meta = p["_meta"]
                            execution_id = meta["decision_id"]
                            existing = outer.db.execute("SELECT result FROM actions WHERE id=?", (execution_id,)).fetchone()
                            if existing:
                                payload = json.loads(existing["result"])
                            else:
                                payload = {"execution_id": execution_id, "tool": tool, "status": "completed", "synthetic": True}
                                if tool == "crm.read": payload["records"] = [{"id": "demo-customer", "classification": "restricted"}]
                                if tool == "access.grant": payload["membership"] = args
                                if tool == "spend.commit": payload["committed_cents"] = args["amount_cents"]
                                outer.db.execute("INSERT INTO actions VALUES(?,?,?,?,?,?)", (execution_id, meta["workflow"], execution_id, tool, canonical(args).decode(), canonical(payload).decode()))
                                outer.db.commit()
                            result = {"content": [{"type": "text", "text": json.dumps(payload)}], "structuredContent": payload, "isError": False}
                    else:
                        self.send_error(400); return
                    raw = canonical({"jsonrpc": "2.0", "id": req.get("id"), "result": result})
                    self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
                except Exception:
                    self.send_error(400)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d/mcp" % self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def actions(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM actions ORDER BY rowid")]

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.db.close()


class Runtime:
    def __init__(self, folder, policy, downstream):
        self.ledger = Ledger(folder)
        try:
            self.ledger.pin_policy(policy.hash)
        except Exception:
            self.ledger.db.close()
            raise
        self.policy, self.downstream = policy, downstream
        # Establish downstream MCP capability handshake using the private credential.
        self._rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "aperture", "version": VERSION}})

    def _rpc(self, method, params):
        return http_json(self.downstream.url, {"jsonrpc": "2.0", "id": uid(), "method": method, "params": params},
                         {"Authorization": "Bearer " + self.downstream.token})["result"]

    def create(self, owner="operator", agents=None, budget=10000, profile="commercial"):
        if type(budget) is not int or not 1 <= budget <= 1000000: raise Fault(400, "invalid budget")
        if profile not in PROFILES: raise Fault(400, "unknown profile; expected one of " + ", ".join(PROFILES))
        agents = agents or ["agent-a", "agent-b"]
        if not isinstance(agents, list) or not agents or any(x not in ["agent-a", "agent-b"] for x in agents): raise Fault(400, "invalid agents")
        w = uid()
        with self.ledger.lock:
            self.ledger.db.execute("INSERT INTO workflows VALUES(?,?,?,?,?,?)", (w, owner, json.dumps(agents), json.dumps({"unresolved": False}), budget, profile))
            self.ledger.append({"kind": "workflow_created", "workflow": w, "owner": owner, "agents": agents, "budget_cents": budget,
                                "profile": profile, "policy_hash": self.policy.hash})
            self.ledger.db.commit()
        return {"id": w, "owner": owner, "agents": agents, "budget_cents": budget, "profile": profile}

    def history(self, w):
        return [{"tool": r["tool"], "arguments": json.loads(r["args"])}
                for r in self.ledger.db.execute("SELECT tool,args FROM history WHERE workflow=? ORDER BY seq", (w,))]

    def policy_input(self, row, tool, args, approval_valid):
        return {"profile": row["profile"], "tool": tool, "arguments": args, "history": self.history(row["id"]),
                "state": {"unresolved": bool(json.loads(row["state"]).get("unresolved"))},
                "budget_cents": row["budget"], "approval_valid": approval_valid}

    def workflow(self, w):
        row = self.ledger.db.execute("SELECT * FROM workflows WHERE id=?", (w,)).fetchone()
        if not row: raise Fault(404, "unknown workflow; agents cannot create or reset workflows")
        return dict(row)

    def approve(self, w, actor, tool, args, ttl=300):
        validate_args(tool, args)
        with self.ledger.lock:
            row = self.workflow(w)
            if actor == row["owner"] or actor in json.loads(row["agents"]): raise Fault(403, "self approval forbidden")
            try:
                terms = self.policy.query("approval_terms", self.policy_input(row, tool, args, False))
            except Exception:
                raise Fault(503, "policy engine unavailable; approvals are not issued")
            if not terms.get("approvable"): raise Fault(400, "policy does not allow an approval to override this action")
            limit = int(terms.get("max_ttl_seconds", 900))
            if type(ttl) is not int or not 1 <= ttl <= limit: raise Fault(400, f"approval expiry must be 1..{limit} seconds for this profile")
            a = uid(); fp = digest({"tool": tool, "arguments": args})
            expires = time.time() + ttl
            self.ledger.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,0)", (a, w, fp, actor, expires))
            self.ledger.append({"kind": "approval", "workflow": w, "profile": row["profile"], "approval_id": a, "approver": actor, "action_hash": fp, "expires": expires})
            self.ledger.db.commit()
            return {"approval_id": a, "expires": expires}

    def call(self, w, agent, tool, args, request_id, approval_id=None, transport_session=None):
        validate_args(tool, args)
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128: raise Fault(400, "request_id required (1..128 characters)")
        start = time.perf_counter()
        l = self.ledger
        with l.lock:  # One process, all policy checks and executions serialized deliberately.
            row = self.workflow(w)
            if agent not in json.loads(row["agents"]): raise Fault(403, "agent is not assigned to this workflow")
            action_hash = digest({"tool": tool, "arguments": args})
            fp = digest({"agent": agent, "action_hash": action_hash, "approval_id": approval_id})
            previous = l.db.execute("SELECT * FROM requests WHERE workflow=? AND request_id=?", (w, request_id)).fetchone()
            if previous:
                if previous["fingerprint"] != fp: raise Fault(409, "request_id cannot be reused for a different action")
                return {**json.loads(previous["result"]), "idempotent_replay": True}
            state = json.loads(row["state"])
            approval = l.db.execute("SELECT * FROM approvals WHERE id=? AND workflow=?", (approval_id, w)).fetchone() if approval_id else None
            valid = bool(approval and not approval["used"] and approval["expires"] > time.time() and approval["fingerprint"] == action_hash)
            value = self.policy_input(row, tool, args, valid)
            policy_start = time.perf_counter()
            engine_error = None
            try:
                decision = self.policy.evaluate(value)
            except Exception:
                decision = {"allow": False, "reasons": ["policy_unavailable"], "overridden": [], "evidence": fallback_evidence(row["profile"], "policy_unavailable")}
                engine_error = "OPA unavailable or invalid response; fail closed"
            policy_ms = round((time.perf_counter() - policy_start) * 1000, 3)
            d = uid()
            l.append({"kind": "decision", "decision_id": d, "workflow": w, "profile": row["profile"], "agent": agent, "initiating_human": row["owner"],
                      "transport_session": transport_session, "request_id": request_id, "tool": tool, "arguments_hash": digest(args),
                      "policy_hash": self.policy.hash, "policy_input": value, "decision": decision, "approval_id": approval_id,
                      "approver": approval["approver"] if valid else None, "policy_ms": policy_ms, "engine_error": engine_error})
            result = {"decision_id": d, "allow": decision["allow"], "reasons": decision["reasons"], "overridden": decision.get("overridden", []),
                      "controls": decision.get("evidence", {}).get("controls", []), "profile": row["profile"], "status": "blocked", "policy_ms": policy_ms}
            if decision["allow"]:
                # Reserve before dispatch: the action joins the policy-visible history now,
                # so an ambiguous outcome still counts toward trajectory and budget rules.
                state["unresolved"] = True
                seq = l.db.execute("SELECT COALESCE(MAX(seq),0)+1 FROM history WHERE workflow=?", (w,)).fetchone()[0]
                l.db.execute("INSERT INTO history VALUES(?,?,?,?,?)", (w, seq, d, tool, canonical(args).decode()))
                if valid: l.db.execute("UPDATE approvals SET used=1 WHERE id=?", (approval_id,))
                l.db.execute("UPDATE workflows SET state=? WHERE id=?", (json.dumps(state), w))
                result["status"] = "unresolved"
            l.db.execute("INSERT INTO requests VALUES(?,?,?,?)", (w, request_id, fp, canonical(result).decode()))
            l.db.commit()  # Signed intent and reservation durable BEFORE side effect.
            if decision["allow"]:
                try:
                    downstream = self._rpc("tools/call", {"name": tool, "arguments": args, "_meta": {"workflow": w, "decision_id": d}})
                    if downstream.get("isError"): raise RuntimeError("tool error")
                    outcome = downstream["structuredContent"]
                    if outcome.get("execution_id") != d: raise RuntimeError("uncorrelated outcome")
                    result.update({"status": "completed", "outcome": outcome})
                    state["unresolved"] = False
                    l.db.execute("UPDATE workflows SET state=? WHERE id=?", (json.dumps(state), w))
                except Exception:
                    result.update({"status": "unresolved", "error": "Downstream result unknown; workflow quarantined; no automatic retry"})
                l.append({"kind": "outcome", "workflow": w, "decision_id": d, "status": result["status"], "outcome": result.get("outcome")})
            result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 3)
            l.db.execute("UPDATE requests SET result=? WHERE workflow=? AND request_id=?", (canonical(result).decode(), w, request_id))
            l.db.commit()
            return result

    def snapshot(self):
        with self.ledger.lock:
            ev = self.ledger.events()
            decisions = [e["body"] for e in ev if e["body"]["kind"] == "decision"]
            actions = self.downstream.actions()
            matched = matched_actions(decisions, actions)
            workflows = []
            for r in self.ledger.db.execute("SELECT * FROM workflows ORDER BY rowid DESC").fetchall():
                item = {**dict(r), "agents": json.loads(r["agents"]), "state": json.loads(r["state"])}
                try:
                    item["summary"] = self.policy.query("summary", {"profile": r["profile"], "history": self.history(r["id"])})
                except Exception:
                    item["summary"] = None  # Display only; enforcement never depends on this.
                workflows.append(item)
            return {"workflows": workflows,
                    "events": ev, "public_key": self.ledger.public, "checkpoint": self.ledger.checkpoint(),
                    "coverage": {"observed_actions": len(actions), "matched_actions": matched, "unmatched_actions": len(actions)-matched,
                                 "percent": round(100*matched/len(actions), 1) if actions else None,
                                 "scope": "Synthetic downstream service only; no account-wide visibility", "unknown": "All other execution paths"},
                    "policy": {"hash": self.policy.hash, "source": self.policy.source, "data": json.loads(self.policy.data_text)},
                    "profiles": {k: {x: v[x] for x in ["label", "summary", "egress_allowlist", "max_approval_ttl_seconds", "sequence_rules", "evidence", "deployment_notes"]}
                                 for k, v in CONFIG["profiles"].items()},
                    "tools": {k: {"tags": v["tags"]} for k, v in CONFIG["tools"].items()},
                    "control_coverage": control_coverage(decisions), "synthetic": True}

    def bundle(self):
        with self.ledger.lock:
            s = self.snapshot()
            b = io.BytesIO()
            with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("events.json", json.dumps(s["events"], indent=2))
                z.writestr("checkpoint.json", json.dumps(s["checkpoint"], indent=2))
                z.writestr("public_key.txt", s["public_key"])
                z.writestr("policy.rego", self.policy.source)
                z.writestr("policy_data.json", self.policy.data_text)
                z.writestr("controls.json", json.dumps(s["control_coverage"], indent=2))
                z.writestr("control-evidence.csv", control_csv(s["events"]))
                z.writestr("downstream.json", json.dumps(self.downstream.actions(), indent=2))
                z.writestr("coverage.json", json.dumps(s["coverage"], indent=2))
                z.writestr("siem.ndjson", "\n".join(json.dumps({"time": e["body"]["timestamp_ns"]/1e9, "sourcetype": "aperture:decision", "event": e}) for e in s["events"]))
                z.writestr("README.txt", "Synthetic pilot evidence. Structured decision inputs are retained locally. No raw model prompts. Verify with verify_bundle.py. Retain the key and checkpoint separately. Policy replay is not agent replay. No certification or complete-coverage claim.\n"
                            "controls.json and control-evidence.csv map decisions to the framework named in each profile. The federal-adjacent mapping to NIST SP 800-53 is a DRAFT that has not been reviewed by an assessor; it indicates where evidence would be offered, not that a control is satisfied.\n")
                files = {name: hashlib.sha256(z.read(name)).hexdigest() for name in z.namelist()}
                body = {"format": "aperture-bundle-v1", "files": files}
                manifest = {"body": body, "signature": base64.b64encode(self.ledger.key.sign(canonical(body))).decode()}
                z.writestr("manifest.json", canonical(manifest))
            return b.getvalue()


def matched_actions(decisions, actions):
    allowed = {d['decision_id']: d for d in decisions if d['decision']['allow']}
    seen = set()
    count = 0
    for a in actions:
        d = allowed.get(a.get('decision_id'))
        try:
            matches = (d is not None and a['id'] == d['decision_id'] and a['id'] not in seen
                       and a['workflow'] == d['workflow'] and a['tool'] == d['tool']
                       and digest(json.loads(a['args'])) == d['arguments_hash']
                       and json.loads(a['result'])['execution_id'] == d['decision_id'])
        except (ValueError, KeyError, TypeError):
            matches = False
        if matches:
            seen.add(a['id']); count += 1
    return count


def control_coverage(decisions):
    """Per profile: how many signed decisions offer evidence toward each mapped control."""
    out = {}
    for d in decisions:
        ev = d["decision"].get("evidence") or {}
        prof = out.setdefault(d.get("profile", "unknown"), {"framework": ev.get("framework", "none"), "decisions": 0, "controls": {}})
        prof["decisions"] += 1
        for c in ev.get("controls", []):
            item = prof["controls"].setdefault(c, {"decisions": 0, "denials": 0})
            item["decisions"] += 1
            item["denials"] += 0 if d["decision"]["allow"] else 1
    return out


def control_csv(events):
    rows = ["control,profile,framework,seq,decision_id,workflow,agent,tool,allow,reasons"]
    for e in events:
        b = e["body"]
        if b["kind"] != "decision": continue
        ev = b["decision"].get("evidence") or {}
        for c in ev.get("controls", []):
            cells = [c, b.get("profile", ""), ev.get("framework", ""), str(b["seq"]), b["decision_id"], b["workflow"], b["agent"], b["tool"],
                     str(b["decision"]["allow"]).lower(), " ".join(b["decision"]["reasons"])]
            rows.append(",".join('"' + x.replace('"', '""') + '"' for x in cells))
    return "\n".join(rows) + "\n"


def make_server(runtime, credentials, port=8080):
    sessions = {}
    session_lock = threading.Lock()
    assurance_lock = threading.Lock()
    report = {"status": "not_run", "tests": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def respond(self, status, value, ctype="application/json", headers=None):
            data = canonical(value) if ctype == "application/json" else value
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
            for k,v in (headers or {}).items(): self.send_header(k,v)
            self.end_headers(); self.wfile.write(data)

        def auth(self, roles):
            given = self.headers.get("Authorization", "")
            for identity, item in credentials.items():
                if hmac.compare_digest(given, "Bearer " + item["token"]):
                    if item["role"] not in roles: raise Fault(403, "role not permitted")
                    return identity
            raise Fault(401, "valid bearer credential required")

        def body(self):
            if self.headers.get("Transfer-Encoding"): raise Fault(400, "chunked body unsupported")
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 < n <= MAX_BODY: raise Fault(413, "body must be 1..131072 bytes")
            value = json.loads(self.rfile.read(n), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
            if not isinstance(value, dict): raise Fault(400, "object required")
            return value

        def guard(self):
            host = self.headers.get("Host", "").split(":")[0]
            if host not in ["127.0.0.1", "localhost"]: raise Fault(403, "loopback host required")
            origin = self.headers.get("Origin")
            if origin and origin not in [f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"]:
                raise Fault(403, "cross-origin request refused")

        def do_GET(self):
            try:
                self.guard()
                if self.path in ["/", "/app.js", "/style.css"]:
                    name, ctype = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}[self.path]
                    return self.respond(200, (ROOT/"web"/name).read_bytes(), ctype)
                if self.path == "/health": return self.respond(200, {"status": "running", "version": VERSION, "mode": "synthetic-pilot"})
                self.auth(["operator", "reviewer"])
                if self.path == "/api/state": return self.respond(200, runtime.snapshot())
                if self.path == "/api/assurance": return self.respond(200, report)
                if self.path == "/api/evidence": return self.respond(200, runtime.bundle(), "application/zip", {"Content-Disposition": 'attachment; filename="aperture-evidence.zip"'})
                if self.path == "/api/siem":
                    events = runtime.snapshot()["events"]
                    lines = "\n".join(json.dumps({"time": e["body"]["timestamp_ns"]/1e9, "sourcetype": "aperture:decision", "event": e}) for e in events)
                    return self.respond(200, lines.encode(), "application/x-ndjson")
                raise Fault(404, "not found")
            except Fault as e: self.respond(e.status, {"error": e.message})

        def do_POST(self):
            try:
                self.guard()
                p = self.body()
                if self.path == "/mcp": return self.mcp(p)
                if self.path == "/api/approvals":
                    actor = self.auth(["reviewer"])
                    return self.respond(200, runtime.approve(p["workflow"], actor, p["tool"], p.get("arguments", {}), p.get("ttl", 300)))
                actor = self.auth(["operator"])
                if self.path == "/api/workflows": return self.respond(201, runtime.create(actor, p.get("agents"), p.get("budget_cents", 10000), p.get("profile", "commercial")))
                if self.path == "/api/demo/call":
                    # Explicit local demo control, operator may exercise either synthetic agent.
                    return self.respond(200, runtime.call(p["workflow"], p.get("agent", "agent-a"), p["tool"], p.get("arguments", {}), p.get("request_id", uid()), p.get("approval_id")))
                if self.path == "/api/verify":
                    snap = runtime.snapshot()
                    return self.respond(200, verify(snap["events"], snap["checkpoint"], snap["public_key"]))
                if self.path == "/api/assurance/run":
                    if not assurance_lock.acquire(False): raise Fault(409, "assurance already running")
                    try:
                        from assurance import run_suite
                        report.clear(); report.update({"status": "running", "tests": []})
                        report.update(run_suite(runtime.policy)); return self.respond(200, report)
                    finally: assurance_lock.release()
                raise Fault(404, "not found")
            except Fault as e: self.respond(e.status, {"error": e.message})
            except (ValueError, KeyError, TypeError): self.respond(400, {"error": "invalid request"})
            except Exception: self.respond(500, {"error": "internal failure; inspect local service"})

        def mcp(self, p):
            agent = self.auth(["agent"])
            if p.get("jsonrpc") != "2.0": raise Fault(400, "JSON-RPC 2.0 required")
            method = p.get("method")
            workflow = self.headers.get("X-Aperture-Workflow", "")
            with runtime.ledger.lock:
                row = runtime.workflow(workflow)
                if agent not in json.loads(row["agents"]): raise Fault(403, "workflow membership required")
            if method == "initialize":
                sid = uid()
                with session_lock:
                    if len(sessions) >= 10000: raise Fault(429, "session limit; restart demo server")
                    sessions[sid] = (agent, workflow)
                return self.respond(200, {"jsonrpc": "2.0", "id": p.get("id"), "result": {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}}, "serverInfo": {"name": "aperture", "version": VERSION}}}, headers={"Mcp-Session-Id": sid})
            sid = self.headers.get("Mcp-Session-Id", "")
            with session_lock:
                if sessions.get(sid) != (agent, workflow): raise Fault(403, "invalid or mismatched MCP session")
            if self.headers.get("MCP-Protocol-Version", PROTOCOL) != PROTOCOL: raise Fault(400, "unsupported protocol version")
            if method == "notifications/initialized": return self.respond(202, b"", "text/plain")
            if method == "tools/list": result = {"tools": TOOLS}
            elif method == "ping": result = {}
            elif method == "tools/call":
                params = p["params"]; meta = params.get("_meta", {})
                rpc_id = p.get("id")
                if type(rpc_id) not in (str, int): raise Fault(400, "tool calls require a string or integer JSON-RPC id")
                explicit_key = meta.get("aperture/idempotency_key")
                if "aperture/idempotency_key" in meta:
                    if not isinstance(explicit_key, str) or not 1 <= len(explicit_key) <= 128:
                        raise Fault(400, "idempotency key must contain 1..128 characters")
                    request_key = "explicit:" + digest(explicit_key)
                else:
                    request_key = "session:" + digest({"session": sid, "rpc_id": rpc_id})
                result_call = runtime.call(workflow, agent, params["name"], params.get("arguments", {}), request_key, meta.get("aperture/approval_id"), sid)
                result = {"content": [{"type": "text", "text": json.dumps(result_call)}], "structuredContent": result_call,
                          "isError": not result_call["allow"] or result_call["status"] != "completed"}
            else: return self.respond(200, {"jsonrpc": "2.0", "id": p.get("id"), "error": {"code": -32601, "message": "method not supported"}})
            return self.respond(200, {"jsonrpc": "2.0", "id": p.get("id"), "result": result})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def load_credentials(folder):
    path = Path(folder)/"credentials.json"
    if path.exists(): return json.loads(path.read_text())
    c = {name: {"role": role, "token": secrets.token_urlsafe(32)} for name, role in [("operator", "operator"), ("reviewer", "reviewer"), ("agent-a", "agent"), ("agent-b", "agent")]}
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: json.dump(c, f, indent=2)
    return c


def start_opa(binary, port, data_path=None):
    load_config(data_path or POLICY_DATA)  # Validate before starting or activating OPA.
    p = subprocess.Popen([str(binary), "run", "--disable-telemetry", "--server", "--addr", f"127.0.0.1:{port}", str(POLICY_REGO), str(data_path or POLICY_DATA)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(60):
        if p.poll() is not None: raise RuntimeError("OPA failed to start; check port and policy")
        try:
            http_json(url + "/health", timeout=.2)
            return p, url
        except Exception: time.sleep(.05)
    p.terminate(); raise RuntimeError("OPA startup timed out")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--opa-port", type=int, default=8181)
    ap.add_argument("--opa", default=str(ROOT/"bin/opa"))
    ap.add_argument("--data", default=str(ROOT/"data"))
    args = ap.parse_args()
    Path(args.data).mkdir(parents=True, exist_ok=True)
    proc, url = start_opa(args.opa, args.opa_port)
    downstream = runtime = server = None
    try:
        downstream = Downstream(args.data)
        runtime = Runtime(args.data, Policy(url), downstream)
        server = make_server(runtime, load_credentials(args.data), args.port)
        print(f"Aperture synthetic pilot: http://127.0.0.1:{server.server_port}", flush=True)
        print(f"Dashboard credentials: {Path(args.data)/'credentials.json'} (operator and reviewer tokens)", flush=True)
        print("Loopback only. Synthetic tools. OPA fail-closed. Ctrl+C to stop.", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server: server.server_close()
        if downstream: downstream.close()
        if runtime: runtime.ledger.db.close()
        proc.terminate(); proc.wait(timeout=5)



if __name__ == "__main__": main()
