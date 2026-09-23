"""Black-box outcome assurance against the actual runtime and synthetic tool HTTP service."""
import concurrent.futures
import copy
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

import os
from pathlib import Path
from aperture import POLICY_DATA, ROOT, Downstream, Fault, Policy, Runtime, canonical, http_json, load_credentials, make_server, start_opa, uid, verify


def run_suite(policy):
    rows = []
    def case(name, control, fn, profile="commercial"):
        started = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="aperture-assurance-") as folder:
            d = Downstream(folder)
            r = Runtime(folder, policy, d)
            w = r.create(profile=profile)
            try:
                evidence = fn(r, d, w["id"])
                rows.append({"name": name, "control": control, "profile": profile, "passed": True, "evidence": evidence, "duration_ms": round((time.perf_counter()-started)*1000, 2)})
            except Exception as e:
                rows.append({"name": name, "control": control, "profile": profile, "passed": False, "evidence": str(e), "duration_ms": round((time.perf_counter()-started)*1000, 2)})
            finally:
                d.close(); r.ledger.db.close()

    def call(r,w,tool,args=None,agent="agent-a",**kw):
        return r.call(w,agent,tool,args or {},kw.pop("request_id",uid()),**kw)
    def check(test, msg):
        if not test: raise AssertionError(msg)
    def denied(r,d,w):
        call(r,w,"crm.read")
        call(r,w,"archive.create")
        a = call(r,w,"external.send",{"destination":"outside.example"})
        check(not a["allow"],"sequence was allowed")
        check(not any(x["tool"]=="external.send" for x in d.actions()),"external action occurred")
        return "Read and archive executed; external transmission absent from independent tool ledger."
    case("Collect → archive → send blocked", "trajectory", denied)

    def noarchive(r,d,w):
        call(r,w,"crm.read")
        a=call(r,w,"external.send",{"destination":"outside.example"})
        check(not a["allow"] and len(d.actions())==1,"direct transmission bypass")
        return "Skipping archive does not evade restricted-source policy."
    case("Direct send after read blocked", "trajectory", noarchive)

    def handoff(r,d,w):
        call(r,w,"crm.read",agent="agent-a")
        a=call(r,w,"external.send",{"destination":"outside.example"},agent="agent-b")
        check(not a["allow"] and len(d.actions())==1,"handoff lost history")
        return "Two separately authenticated demo agents share server-owned workflow state."
    case("Agent handoff preserves restriction", "identity", handoff)

    def benign(r,d,w):
        a=call(r,w,"external.send",{"destination":"outside.example"})
        check(a["status"]=="completed" and len(d.actions())==1,"legitimate action blocked")
        return "Unrestricted workflow transmission succeeds."
    case("Legitimate unrestricted send succeeds", "regression", benign)

    def approval(r,d,w):
        args={"subject":"employee-demo","role":"reader"}
        first=call(r,w,"access.grant",args)
        check(not first["allow"] and len(d.actions())==0,"unapproved access granted")
        ap=r.approve(w,"reviewer","access.grant",args)["approval_id"]
        second=call(r,w,"access.grant",args,approval_id=ap)
        check(second["status"]=="completed" and len(d.actions())==1,"approved action missing")
        return "No membership before approval; exact approved membership recorded afterward."
    case("Approval controls actual access grant", "approval", approval)

    def substitution(r,d,w):
        ap=r.approve(w,"reviewer","access.grant",{"subject":"employee-demo","role":"reader"})["approval_id"]
        a=call(r,w,"access.grant",{"subject":"employee-demo","role":"admin"},approval_id=ap)
        check(not a["allow"] and not d.actions(),"substituted role granted")
        return "Reader approval cannot authorize administrator role."
    case("Parameter substitution rejected", "approval", substitution)

    def reuse(r,d,w):
        args={"subject":"employee-demo","role":"reader"}
        ap=r.approve(w,"reviewer","access.grant",args)["approval_id"]
        call(r,w,"access.grant",args,approval_id=ap)
        a=call(r,w,"access.grant",args,approval_id=ap)
        check(not a["allow"] and len(d.actions())==1,"approval replay executed twice")
        return "Approval consumed exactly once; second action absent downstream."
    case("Approval replay rejected", "approval", reuse)

    def expiry(r,d,w):
        args={"subject":"employee-demo","role":"reader"}
        ap=r.approve(w,"reviewer","access.grant",args)["approval_id"]
        r.ledger.db.execute("UPDATE approvals SET expires=0 WHERE id=?",(ap,));r.ledger.db.commit()
        a=call(r,w,"access.grant",args,approval_id=ap)
        check(not a["allow"] and not d.actions(),"expired approval used")
        return "Expired approval rejected; no membership created."
    case("Expired approval rejected", "approval", expiry)

    def selfapprove(r,d,w):
        try: r.approve(w,"operator","access.grant",{"subject":"employee-demo","role":"reader"})
        except Fault as e:
            check(e.status==403,"wrong rejection");return "Workflow initiator cannot approve own action."
        raise AssertionError("self-approval accepted")
    case("Separation of duties enforced", "approval", selfapprove)

    def budget(r,d,w):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(lambda _:call(r,w,"spend.commit",{"amount_cents":6000}),range(2)))
        actual=sum(json.loads(x["args"]).get("amount_cents",0) for x in d.actions())
        check(sum(x["allow"] for x in outcomes)==1 and actual==6000,"parallel overspend")
        return "Concurrent 6000-cent actions against 10000-cent cap commit only 6000 cents."
    case("Concurrent spend cannot exceed cap", "concurrency", budget)

    def retry(r,d,w):
        a=call(r,w,"spend.commit",{"amount_cents":1000},request_id="same-id")
        b=call(r,w,"spend.commit",{"amount_cents":1000},request_id="same-id")
        check(a["decision_id"]==b["decision_id"] and len(d.actions())==1,"duplicate execution")
        try: call(r,w,"spend.commit",{"amount_cents":2000},request_id="same-id")
        except Fault as e:
            check(e.status==409,"incorrect conflict");return "Same request returns cached result; altered retry conflicts."
        raise AssertionError("altered retry accepted")
    case("Idempotent retries and conflicts", "concurrency", retry)

    def unknown(r,d,w):
        a=call(r,w,"shell.execute",{"cmd":"synthetic"})
        check(not a["allow"] and not d.actions(),"unknown tool executed")
        return "Unregistered tool denied by OPA before dispatch."
    case("Unknown tools fail closed", "boundary", unknown)

    def bypass(r,d,w):
        try: http_json(d.url,{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"access.grant","arguments":{"subject":"x","role":"admin"}}})
        except urllib.error.HTTPError as e:
            check(e.code==401 and not d.actions(),"direct route not rejected");return "Direct HTTP tool call without proxy credential returns 401."
        raise AssertionError("direct unauthenticated bypass succeeded")
    case("Direct downstream bypass rejected", "boundary", bypass)

    def outage(r,d,w):
        r.policy=Policy("http://127.0.0.1:1")
        a=call(r,w,"crm.read")
        check(not a["allow"] and a["reasons"]==["policy_unavailable"] and not d.actions(),"OPA outage failed open")
        return "OPA unavailable: deny persisted; no downstream action."
    case("Policy outage fails closed", "resilience", outage)

    def unresolved(r,d,w):
        d.fail_next=True
        a=call(r,w,"spend.commit",{"amount_cents":1000},request_id="uncertain")
        b=call(r,w,"crm.read")
        check(a["status"]=="unresolved" and not b["allow"] and not d.actions(),"uncertain workflow continued")
        c=call(r,w,"spend.commit",{"amount_cents":1000},request_id="uncertain")
        check(c["status"]=="unresolved" and not d.actions(),"ambiguous call retried")
        return "Unknown outcome quarantines workflow and remains reserved; no automatic retry."
    case("Unknown outcome quarantines workflow", "resilience", unresolved)

    def persisted(r,d,w):
        call(r,w,"crm.read")
        # Open a new runtime against the persisted workflow and original downstream.
        other=Runtime(r.ledger.folder,policy,d)
        try:
            a=call(other,w,"external.send",{"destination":"outside.example"})
            check(not a["allow"],"restart erased history")
        finally:other.ledger.db.close()
        return "Restriction survives runtime reconstruction from SQLite."
    case("State survives restart", "resilience", persisted)

    def integrity(r,d,w):
        call(r,w,"crm.read")
        s=r.snapshot();verify(s["events"],s["checkpoint"],s["public_key"])
        tampered=copy.deepcopy(s["events"]);tampered[0]["body"]["owner"]="intruder"
        for variant in [tampered,s["events"][:-1]]:
            try:verify(variant,s["checkpoint"],s["public_key"])
            except Exception:continue
            raise AssertionError("tamper or truncation accepted")
        return "Ed25519 verification accepts original and rejects tamper/truncation against checkpoint."
    case("Signed chain and checkpoint verification", "evidence", integrity)

    def replay(r,d,w):
        call(r,w,"crm.read");call(r,w,"external.send",{"destination":"outside.example"})
        count=0
        for event in r.snapshot()["events"]:
            b=event["body"]
            if b["kind"]=="decision":
                check(policy.evaluate(b["policy_input"])==b["decision"],"decision replay mismatch");count+=1
        check(count==2,"missing evidence")
        return "Both allow and deny reproduce from recorded inputs using the same Rego policy."
    case("Policy decisions replay exactly", "evidence", replay)

    def negative(r,d,w):
        class BrokenPolicy:
            hash=policy.hash
            source=policy.source
            def evaluate(self,value):return {"allow":True,"reasons":[]}
        r.policy=BrokenPolicy()
        a=call(r,w,"access.grant",{"subject":"employee-demo","role":"admin"})
        finding=any(x["tool"]=="access.grant" for x in d.actions())
        check(finding and a["allow"],"negative control did not exercise real side effect")
        return "Assurance correctly detects unauthorized membership with intentionally disabled policy. TEST FIXTURE ONLY."
    case("Negative control exposes broken enforcement", "assurance-calibration", negative)

    def mcp(r,d,w):
        creds=load_credentials(r.ledger.folder)
        server=make_server(r,creds,0)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        url=f"http://127.0.0.1:{server.server_port}/mcp"
        def req(agent,method,params=None,sid=None,workflow=w):
            h={"Content-Type":"application/json","Authorization":"Bearer "+creds[agent]["token"],"X-Aperture-Workflow":workflow,"MCP-Protocol-Version":"2025-11-25"}
            if sid:h["Mcp-Session-Id"]=sid
            q=urllib.request.Request(url,data=canonical({"jsonrpc":"2.0","id":uid(),"method":method,"params":params or {}}),headers=h)
            with urllib.request.urlopen(q) as resp:return json.loads(resp.read()),resp.headers.get("Mcp-Session-Id")
        try:
            _,sid=req("agent-a","initialize")
            req("agent-a","tools/call",{"name":"crm.read","arguments":{}},sid)
            _,sid2=req("agent-b","initialize")
            out,_=req("agent-b","tools/call",{"name":"external.send","arguments":{"destination":"outside.example"}},sid2)
            check(out["result"]["isError"] and len(d.actions())==1,"MCP reinitialization reset state")
            try:req("agent-a","tools/list",sid=sid2)
            except urllib.error.HTTPError as e:check(e.code==403,"identity mismatch accepted")
            else:raise AssertionError("stolen transport session accepted")
            try:req("agent-a","initialize",workflow=uid())
            except urllib.error.HTTPError as e:check(e.code==404,"unknown workflow accepted")
            else:raise AssertionError("agent created a new workflow")
            return "Actual MCP HTTP handshakes: session restart/handoff preserves history; stolen session and invented workflow refused."
        finally:server.shutdown();server.server_close()
    case("MCP transport identity and session reset", "protocol", mcp)


    # ---- v0.2: trajectory rules as policy data, and profile behavior ----
    def sends(d):return [x for x in d.actions() if x["tool"]=="external.send"]

    def override(r,d,w):
        call(r,w,"crm.read")
        dest={"destination":"outside.example"}
        first=call(r,w,"external.send",dest)
        check(not first["allow"] and not sends(d),"unapproved restricted send executed")
        ap=r.approve(w,"reviewer","external.send",dest)["approval_id"]
        second=call(r,w,"external.send",dest,approval_id=ap)
        check(second["status"]=="completed" and second["overridden"]==["restricted_data_external_send"] and len(sends(d))==1,"approval did not override approvable rule")
        return "Approvable trajectory rule yields to an exact approval; the override is named in the signed decision."
    case("Commercial: approval overrides restricted send", "trajectory", override)

    def isolation(r,d,w):
        dest={"destination":"outside.example"}
        c=call(r,w,"external.send",dest)
        f=r.create(profile="federal")["id"]
        x=call(r,f,"external.send",dest)
        check(c["allow"] and not x["allow"] and "egress_destination_not_allowlisted" in x["reasons"] and len(sends(d))==1,"profiles leaked or egress not enforced")
        return "Same action, two workflows: commercial allows it, federal-adjacent denies a non-allowlisted destination."
    case("Profiles are isolated per workflow", "profile", isolation)

    def egress(r,d,w):
        call(r,w,"crm.read")
        dest={"destination":"outside.example"}
        ap=r.approve(w,"reviewer","external.send",dest)["approval_id"]
        a=call(r,w,"external.send",dest,approval_id=ap)
        check(not a["allow"] and a["reasons"]==["egress_destination_not_allowlisted"] and not sends(d),"approval overrode the egress allowlist")
        check("SC-7" in a["controls"] and "AC-4" in a["controls"],"federal evidence mapping missing")
        return "Approval satisfies the CUI rule but cannot override the egress allowlist; AC-4 and SC-7 attached as draft evidence."
    case("Federal: egress allowlist is not approvable", "egress", egress, "federal")

    def staged(r,d,w):
        call(r,w,"crm.read");call(r,w,"archive.create")
        dest={"destination":"partner.example"}
        ap=r.approve(w,"reviewer","external.send",dest)["approval_id"]
        a=call(r,w,"external.send",dest,approval_id=ap)
        check(not a["allow"] and a["reasons"]==["staged_exfiltration"] and not sends(d),"staged exfiltration was approvable")
        return "Read, stage, send to an allowlisted partner: still denied; the three-step rule is non-overridable in this profile."
    case("Federal: staged exfiltration cannot be approved", "trajectory", staged, "federal")

    def cui_ok(r,d,w):
        call(r,w,"crm.read")
        dest={"destination":"partner.example"}
        ap=r.approve(w,"reviewer","external.send",dest,ttl=300)["approval_id"]
        a=call(r,w,"external.send",dest,approval_id=ap)
        check(a["status"]=="completed" and len(sends(d))==1 and "AC-5" in a["controls"],"legitimate approved CUI send blocked")
        return "Approved CUI send to an allowlisted destination succeeds; AC-5 attached for the approval."
    case("Federal: approved send to allowlisted partner", "regression", cui_ok, "federal")

    def ttl(r,d,w):
        try:r.approve(w,"reviewer","access.grant",{"subject":"employee-demo","role":"reader"},ttl=900)
        except Fault as e:
            check(e.status==400,"wrong rejection");return "Federal profile caps approval lifetime at 300 seconds; a 900-second approval is refused."
        raise AssertionError("long-lived approval accepted")
    case("Federal: approval lifetime capped by profile", "approval", ttl, "federal")

    def data_driven(r,d,w):
        call(r,w,"crm.read")
        b=[e["body"] for e in r.snapshot()["events"] if e["body"]["kind"]=="decision"][-1]
        check(set(b["policy_input"]["state"])=={"unresolved"} and b["policy_input"]["history"]==[],"gateway still precomputes trajectory state")
        # Retag one tool in a copy of the policy data; no code changes.
        data=json.loads(POLICY_DATA.read_text())
        data["aperture_config"]["tools"]["archive.create"]["tags"].append("source:restricted")
        binary=ROOT/"bin"/("opa.exe" if os.name=="nt" else "opa")
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"aperture_data.json";path.write_text(json.dumps(data))
            proc,url=start_opa(binary,8383,path)
            try:
                alt=Policy(url,data_text=path.read_text())
                fresh=Path(tmp)/"new-ledger"
                other=Runtime(fresh,alt,d)
                w2=other.create()["id"]
                try:
                    call(other,w2,"archive.create")
                    a=call(other,w2,"external.send",{"destination":"outside.example"})
                finally:other.ledger.db.close()
            finally:proc.terminate();proc.wait(timeout=5)
        check(not a["allow"] and a["reasons"]==["restricted_data_external_send"] and alt.hash!=policy.hash,"data change did not change behavior")
        return "Policy input carries history, not flags. Retagging one tool in data changed enforcement with no code change, under a new policy hash."
    case("Trajectory rules are policy data, not code", "policy-as-code", data_driven)

    from regression_assurance import run_regressions
    rows.extend(run_regressions(policy))

    return {"status":"completed", "passed":sum(r["passed"] for r in rows), "total":len(rows), "tests":rows,
            "scope":"Isolated synthetic tools over HTTP, same OPA and runtime code. Not customer validation or universal safety proof.",
            "finished_at":time.time(), "policy_hash":policy.hash}


if __name__ == "__main__":
    import argparse
    import subprocess
    from pathlib import Path
    from aperture import ROOT, start_opa
    ap=argparse.ArgumentParser();ap.add_argument("--output",default="assurance-report.json");ap.add_argument("--opa",default=str(ROOT/"bin/opa"));ap.add_argument("--opa-port",type=int,default=8282)
    args=ap.parse_args();proc,url=start_opa(args.opa,args.opa_port)
    try:
        report=run_suite(Policy(url));Path(args.output).write_text(json.dumps(report,indent=2))
        for r in report["tests"]:print(("PASS" if r["passed"] else "FAIL")+"  "+r["name"]+" — "+r["evidence"])
        print(f"{report['passed']}/{report['total']} passed")
        raise SystemExit(0 if report["passed"]==report["total"] else 1)
    finally:proc.terminate();proc.wait(timeout=5)
