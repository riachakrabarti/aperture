"""Run the live demo and evidence verification in one isolated local process tree."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time
from aperture import ROOT,http_json

ap=argparse.ArgumentParser();ap.add_argument('--browser',action='store_true');args=ap.parse_args()
proc=subprocess.Popen([sys.executable,str(ROOT/'aperture.py'),'--opa-port','8582'],cwd=ROOT,stdout=subprocess.DEVNULL)
try:
    for _ in range(80):
        if proc.poll() is not None:raise RuntimeError('app startup failed')
        try:http_json('http://127.0.0.1:8080/health',timeout=.2);break
        except Exception:time.sleep(.05)
    else:raise RuntimeError('app startup timeout')
    subprocess.run([sys.executable,'demo.py','--output','sample-evidence'],cwd=ROOT,check=True)
    r=subprocess.run([sys.executable,'verify_bundle.py','sample-evidence/evidence.zip','--trusted-key','sample-evidence/trusted-public-key.txt','--checkpoint','sample-evidence/checkpoint.json','--opa',str(ROOT/'bin/opa')],cwd=ROOT,capture_output=True,text=True,check=True)
    (ROOT/'sample-evidence/verification-result.txt').write_text(r.stdout);print(r.stdout)
    if args.browser:subprocess.run(['node','qa_browser.cjs'],cwd=ROOT,check=True)
finally:
    proc.send_signal(2)
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
