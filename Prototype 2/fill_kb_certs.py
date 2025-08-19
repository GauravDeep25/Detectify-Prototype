#!/usr/bin/env python3
"""
fill_kb_certs.py
Populate cert_sha256 and official_apk_sha256 fields in official_reference.json.
Requires:
  - gplaycli (recommended) OR you must have APKs on disk (pulled from device).
  - apksigner (from Android build-tools) on PATH
  - Python 3
Usage:
  python3 fill_kb_certs.py official_reference.json
"""

import json, subprocess, sys, tempfile, os, hashlib, shutil
from pathlib import Path

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout

def apk_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_cert_sha256(apk_path):
    # uses apksigner verify --print-certs
    apk_signer = shutil.which("apksigner")
    if not apk_signer:
        print("[!] apksigner not found on PATH. Install Android build-tools and add apksigner to PATH.")
        return None
    rc, out = run([apk_signer, "verify", "--print-certs", apk_path])
    if rc != 0:
        # sometimes apksigner returns non-zero for unverifiable; still try to parse
        pass
    for line in out.splitlines():
        line = line.strip()
        if "certificate SHA-256 digest:" in line:
            val = line.split(":",1)[1].strip().replace(" ", "").lower()
            return val
    # fallback: try to parse META-INF/*.RSA via keytool (not implemented here)
    return None

def download_with_gplaycli(package, dest_dir):
    gplay = shutil.which("gplaycli") or shutil.which("gplay")
    if not gplay:
        return None
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"[+] Using gplaycli to download {package} ...")
    # gplaycli -d <package> -f <folder>
    rc, out = run([gplay, "-d", package, "-f", str(dest_dir)])
    if rc != 0:
        print("[!] gplaycli failed:", out)
        return None
    # find apk in dest_dir
    for p in dest_dir.glob("*.apk"):
        return str(p)
    # sometimes gplaycli outputs nested folder
    for p in dest_dir.rglob("*.apk"):
        return str(p)
    return None

def main(kb_path):
    kb_path = Path(kb_path)
    kb = json.loads(kb_path.read_text(encoding="utf-8"))
    tmp = Path(tempfile.mkdtemp(prefix="kb_apk_"))
    print("[*] temp dir:", tmp)
    modified = False

    # iterate through banks section
    for bank in kb.get("banks", []):
        for pkg in bank.get("packages", []):
            pid = pkg.get("id")
            print("\n=== Processing:", pid)
            # try to download via gplaycli
            apk = download_with_gplaycli(pid, tmp)
            if not apk:
                print(f"[!] Could not auto-download {pid}.")
                print("    Option A: install the app on an Android device and use `adb shell pm path <package>` then `adb pull` to get the APK.")
                print("    Option B: install Aurora Store on Android and download APK, then copy to this machine.")
                continue
            print("[+] Got APK:", apk)
            cert = get_cert_sha256(apk)
            sh = apk_sha256(apk)
            print(f"    cert_sha256: {cert}")
            print(f"    apk_sha256: {sh}")
            if cert:
                # write into list, avoid duplicates
                existing = pkg.get("cert_sha256", [])
                if cert not in existing:
                    existing.append(cert)
                    pkg["cert_sha256"] = existing
                pkg["official_apk_sha256"] = pkg.get("official_apk_sha256", [])
                if sh not in pkg["official_apk_sha256"]:
                    pkg["official_apk_sha256"].append(sh)
                modified = True

    # UPI apps
    for up in kb.get("upi_apps", []):
        pid = up.get("package")
        print("\n=== Processing UPI:", pid)
        apk = download_with_gplaycli(pid, tmp)
        if not apk:
            print(f"[!] Could not auto-download {pid}. See note above for manual pull.")
            continue
        cert = get_cert_sha256(apk)
        sh = apk_sha256(apk)
        print(f"    cert_sha256: {cert}")
        print(f"    apk_sha256: {sh}")
        if cert:
            existing = up.get("cert_sha256", [])
            if cert not in existing:
                existing.append(cert)
                up["cert_sha256"] = existing
            up["official_apk_sha256"] = up.get("official_apk_sha256", [])
            if sh not in up["official_apk_sha256"]:
                up["official_apk_sha256"].append(sh)
            modified = True

    if modified:
        backup = kb_path.with_suffix(".bak.json")
        backup.write_text(kb_path.read_text(encoding="utf-8"), encoding="utf-8")
        print("[*] Backed up original KB to", backup)
        kb_path.write_text(json.dumps(kb, indent=2, ensure_ascii=False), encoding="utf-8")
        print("[+] Updated KB written to", kb_path)
    else:
        print("[*] No changes made to KB. Either gplaycli unavailable or downloads failed.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 fill_kb_certs.py official_reference.json")
        sys.exit(1)
    main(sys.argv[1])
