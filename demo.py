"""Exercise two MCP clients through the live gateway, then export evidence."""
import argparse
import json
from pathlib import Path
import urllib.request
from aperture import canonical, http_json, uid

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--url",default="http://127.0.0.1:8080");ap.add_argument("--credentials",default="data/credentials.json");ap.add_argument("--output",default="demo-output");ap.add_argument("--profile",choices=["commercial","federal","both"],default="both")
    a=ap.parse_args();c=json.loads(Path(a.credentials).read_text());out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
    def headers(who):return {"Authorization":"Bearer "+c[who]["token"]}
    steps=[]
    def run(profile):
        workflow=http_json(a.url+"/api/workflows",{"budget_cents":10000,"profile":profile},headers("operator"))["id"]
        sessions={}
        def mcp(who,method,params):
            h={**headers(who),"Content-Type":"application/json","X-Aperture-Workflow":workflow,"MCP-Protocol-Version":"2025-11-25"}
            if who in sessions:h["Mcp-Session-Id"]=sessions[who]
            req=urllib.request.Request(a.url+"/mcp",data=canonical({"jsonrpc":"2.0","id":uid(),"method":method,"params":params}),headers=h)
            with urllib.request.urlopen(req) as r:
                if r.headers.get("Mcp-Session-Id"):sessions[who]=r.headers["Mcp-Session-Id"]
                return json.loads(r.read())["result"]
        for who in ["agent-a","agent-b"]:mcp(who,"initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":who,"version":"1"}})
        def action(who,tool,args=None,approval=None):
            p={"name":tool,"arguments":args or {}}
            if approval:p["_meta"]={"aperture/approval_id":approval}
            result=mcp(who,"tools/call",p)["structuredContent"]
            steps.append({"profile":profile,"agent":who,"tool":tool,"result":result})
            print(f"[{profile}]",who,tool,"ALLOW" if result["allow"] else "DENY",result["status"],",".join(result["reasons"]))
        def approve(tool,args):
            return http_json(a.url+"/api/approvals",{"workflow":workflow,"tool":tool,"arguments":args,"ttl":300},headers("reviewer"))["approval_id"]
        action("agent-a","crm.read")
        action("agent-a","archive.create")
        out_args={"destination":"outside.example" if profile=="commercial" else "partner.example"}
        action("agent-b","external.send",out_args)
        # Commercial: approval overrides the staged pattern. Federal: staged exfiltration is not approvable.
        action("agent-b","external.send",out_args,approve("external.send",out_args))
        args={"subject":"employee-demo","role":"reader"}
        action("agent-b","access.grant",args)
        approval=approve("access.grant",args)
        action("agent-b","access.grant",args,approval)
        action("agent-b","access.grant",args,approval)
        action("agent-a","spend.commit",{"amount_cents":6000})
        action("agent-b","spend.commit",{"amount_cents":6000})
    for profile in (["commercial","federal"] if a.profile=="both" else [a.profile]):run(profile)
    snap=http_json(a.url+"/api/state",headers=headers("operator"))
    (out/"trusted-public-key.txt").write_text(snap["public_key"])
    (out/"checkpoint.json").write_text(json.dumps(snap["checkpoint"],indent=2))
    (out/"demo-results.json").write_text(json.dumps(steps,indent=2))
    req=urllib.request.Request(a.url+"/api/evidence",headers=headers("operator"))
    with urllib.request.urlopen(req) as r:(out/"evidence.zip").write_bytes(r.read())
    print("Exported evidence and separately captured checkpoint to",out)

if __name__=="__main__":main()
