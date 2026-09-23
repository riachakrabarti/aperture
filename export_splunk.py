"""Explicit, operator-invoked HEC export. Not invoked automatically."""
import argparse
import json
import os
from pathlib import Path
import urllib.request
from urllib.parse import urlparse

def main():
    ap=argparse.ArgumentParser();ap.add_argument("input",help="siem.ndjson from evidence bundle");ap.add_argument("--url",required=True,help="HTTPS Splunk HEC /services/collector/event endpoint");ap.add_argument("--token-env",default="APERTURE_HEC_TOKEN")
    a=ap.parse_args()
    if urlparse(a.url).scheme!="https":raise SystemExit("HTTPS required")
    token=os.environ.get(a.token_env)
    if not token:raise SystemExit("Set the named token environment variable")
    # Validate the complete batch before sending anything. Do not retry automatically.
    lines=Path(a.input).read_text().splitlines()
    for line in lines:
        value=json.loads(line)
        if "event" not in value or value.get("sourcetype")!="aperture:decision":raise SystemExit("Unexpected event format")
    data="\n".join(lines).encode()
    req=urllib.request.Request(a.url,data=data,headers={"Authorization":"Splunk "+token,"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=20) as r:
        result=json.loads(r.read())
        if result.get("code")!=0:raise SystemExit("HEC did not accept batch: "+str(result))
    print(f"HEC accepted {len(lines)} records. Search visibility and index permissions require customer validation.")

if __name__=="__main__":main()
