"""Regenerate site/demo (the browser sandbox) from web/ and policies/.

Run after changing the dashboard or the policy:  python tools/build_site_demo.py
Requires the OPA binary from `python setup.py` to compile the policy to WebAssembly.
The vendored browser libraries in site/demo/vendor are not touched.
"""
import argparse
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "site" / "demo"
ENTRYPOINTS = ["aperture/decision", "aperture/approval_terms", "aperture/summary"]
BANNER = ('<div class="sandbox-banner" role="note"><strong>Browser sandbox.</strong> The real dashboard and the real Rego policy '
          '(compiled to WebAssembly) running entirely in this tab. Tools are synthetic, state resets on reload, and a fresh '
          'Ed25519 key is generated for this session. <a href="/" target="_top">Back to overview</a></div>')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--opa", default=str(ROOT / "bin" / "opa"))
    args = ap.parse_args()
    (DEMO / "policy").mkdir(parents=True, exist_ok=True)
    html = (ROOT / "web" / "index.html").read_text()
    for needed in ['href="/style.css"', '<script src="/app.js" defer></script>', "<main>"]:
        if needed not in html: raise SystemExit("web/index.html changed shape; update this script")
    html = html.replace('href="/style.css"', 'href="/demo/style.css"')
    html = html.replace('<script src="/app.js" defer></script>', '<script type="module" src="/demo/sandbox.js"></script><script src="/demo/app.js" defer></script>')
    html = html.replace("<title>Aperture | Runtime & assurance</title>", "<title>Aperture | Live sandbox</title>")
    html = html.replace("<main>", "<main>" + BANNER, 1)
    (DEMO / "index.html").write_text(html)
    shutil.copy(ROOT / "web" / "app.js", DEMO / "app.js")
    css = (ROOT / "web" / "style.css").read_text()
    css += ("\n.sandbox-banner{margin:14px 0 0;padding:10px 14px;border-radius:5px;background:#fff6e0;border:1px solid #ecd9a4;"
            "color:#5b4a17;font-size:12px}.sandbox-banner a{color:inherit;margin-left:6px}\n")
    (DEMO / "style.css").write_text(css)
    shutil.copy(ROOT / "policies" / "controls.rego", DEMO / "policy" / "controls.rego")
    shutil.copy(ROOT / "policies" / "aperture_data.json", DEMO / "policy" / "aperture_data.json")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "bundle.tar.gz"
        cmd = [args.opa, "build", "-t", "wasm", "-o", str(out)]
        for e in ENTRYPOINTS: cmd += ["-e", e]
        cmd.append(str(ROOT / "policies" / "controls.rego"))
        subprocess.run(cmd, check=True)
        with tarfile.open(out) as t:
            member = next(m for m in t.getmembers() if m.name.lstrip("/") == "policy.wasm")
            (DEMO / "policy" / "policy.wasm").write_bytes(t.extractfile(member).read())
    print("site/demo regenerated")


if __name__ == "__main__":
    main()
