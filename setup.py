"""Download a pinned OPA release for the local architecture; not a Python packaging file."""
import hashlib
import os
from pathlib import Path
import platform
import urllib.request

VERSION="1.0.1"
root=Path(__file__).resolve().parent
system={"Linux":"linux","Darwin":"darwin","Windows":"windows"}.get(platform.system())
arch={"x86_64":"amd64","AMD64":"amd64","arm64":"arm64","aarch64":"arm64"}.get(platform.machine())
if not system or not arch:raise SystemExit("Unsupported platform; install OPA 1.0.1 manually and pass --opa PATH")
suffix="_static" if system=="linux" else ".exe" if system=="windows" else ""
name=f"opa_{system}_{arch}{suffix}"
target=root/"bin"/("opa.exe" if system=="windows" else "opa")
if system=="linux" and arch=="amd64" and target.exists():
    expected=(root/"bin/opa.sha256").read_text().split()[0]
    if hashlib.sha256(target.read_bytes()).hexdigest()!=expected:raise SystemExit("Bundled OPA checksum mismatch")
    target.chmod(0o755)
    print("Bundled Linux OPA checksum verified.")
else:
    base=f"https://github.com/open-policy-agent/opa/releases/download/v{VERSION}/"
    print(f"Downloading pinned OPA {VERSION} for {system}/{arch} from official GitHub release.")
    with urllib.request.urlopen(base+name,timeout=90) as r:data=r.read()
    with urllib.request.urlopen(base+name+".sha256",timeout=30) as r:expected=r.read().decode().split()[0]
    if hashlib.sha256(data).hexdigest()!=expected:raise SystemExit("Official release checksum mismatch")
    target.parent.mkdir(exist_ok=True);target.write_bytes(data);target.chmod(0o755)
    print("Downloaded release checksum verified.")
print("Next: python aperture.py" + (" --opa bin/opa.exe" if system=="windows" else ""))
