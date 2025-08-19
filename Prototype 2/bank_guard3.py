#!/usr/bin/env python3
# bank_guard3.py — 3-layer verification using official_reference.json

import argparse, json, hashlib, tempfile, shutil, subprocess, re, os, sys
from pathlib import Path

# ---- config ----
KB_FILE = "official_reference.json"

DANGEROUS_PERMS = {
    "READ_SMS","RECEIVE_SMS","SEND_SMS","READ_CALL_LOG","WRITE_CALL_LOG","RECORD_AUDIO",
    "CAMERA","READ_CONTACTS","WRITE_CONTACTS","READ_PHONE_STATE","ANSWER_PHONE_CALLS",
    "READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE","REQUEST_INSTALL_PACKAGES","WRITE_SETTINGS"
}

URL_RE = re.compile(r"(http[s]?://[A-Za-z0-9\.\-_:~%#/?=&]+)")
IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def which(cmd): return shutil.which(cmd)

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout

def sha256_file(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def aapt_badging(apk_path):
    aapt = which("aapt") or which("aapt2")
    if not aapt:
        return {}
    rc,out = run([aapt, "dump", "badging", str(apk_path)])
    pkg=None; label=None; version=None
    for line in out.splitlines():
        if line.startswith("package:"):
            m = re.search(r"name='([^']+)'", line)
            if m: pkg = m.group(1)
            m2 = re.search(r"versionName='([^']+)'", line)
            if m2: version = m2.group(1)
        if line.startswith("application-label"):
            m = re.search(r"application-label(?:-\w+)?:'([^']+)'", line)
            if m: label = m.group(1)
    return {"package":pkg,"label":label,"version":version}

def apksigner_cert_sha256(apk_path):
    apksigner = which("apksigner")
    if not apksigner:
        return None
    rc,out = run([apksigner, "verify", "--print-certs", str(apk_path)])
    for line in out.splitlines():
        if "certificate SHA-256 digest" in line:
            return line.split(":",1)[1].strip().replace(" ","").lower()
    return None

def aapt_permissions(apk_path):
    aapt = which("aapt") or which("aapt2")
    if not aapt:
        return set()
    rc,out = run([aapt,"dump","badging",str(apk_path)])
    perms=set()
    for l in out.splitlines():
        if l.startswith("uses-permission:"):
            m = re.search(r"name='([^']+)'", l)
            if m:
                perms.add(m.group(1).split(".")[-1])
    return perms

def jadx_decompile(apk_path, outdir):
    jadx = which("jadx")
    if not jadx:
        return False
    try:
        rc,out = run([jadx, "-d", str(outdir), str(apk_path)])
        return True
    except Exception:
        return False

def scan_sources(srcdir):
    apis=[]; urls=[]; ips=[]
    for p in Path(srcdir).rglob("*.java"):
        try:
            txt = p.read_text(errors="ignore")
        except:
            continue
        for m in URL_RE.findall(txt):
            urls.append(f"{m} :: {p.relative_to(srcdir)}")
        for m in IP_RE.findall(txt):
            ips.append(f"{m} :: {p.relative_to(srcdir)}")
        # simple suspicious keywords (you can extend)
        for kw in ["DexClassLoader","Runtime.getRuntime().exec","SmsManager.sendTextMessage","getDeviceId(","getImei(","BIND_ACCESSIBILITY_SERVICE","addJavascriptInterface","WebView.setWebContentsDebuggingEnabled","ClipboardManager"]:
            if kw in txt:
                apis.append(f"{kw} :: {p.relative_to(srcdir)}")
    return {"apis":sorted(set(apis)),"urls":sorted(set(urls)),"ips":sorted(set(ips))}

def load_kb(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def find_kb_entry(kb, package):
    for b in kb.get("banks",[]):
        for pkg in b.get("packages",[]):
            if pkg.get("id")==package:
                rec = dict(pkg); rec["_bank"]=b.get("bank"); rec["_is_bank"]=True; return rec
    for u in kb.get("upi_apps",[]):
        if u.get("package")==package:
            rec = dict(u); rec["_bank"]=u.get("name"); rec["_is_bank"]=False; return rec
    return None

def filter_endpoints(urls, allowlist):
    allowed=[]; unknown=[]; clear=[]
    for u in urls:
        url = u.split(" :: ")[0]
        if url.startswith("http://"):
            clear.append(u)
        dom = None
        m = re.search(r"https?://([^/]+)", url)
        if m: dom = m.group(1).lower()
        if dom:
            if any(dom==d or dom.endswith("."+d) for d in allowlist):
                allowed.append(u)
            else:
                unknown.append(u)
        else:
            unknown.append(u)
    return {"allowed":allowed,"unknown":unknown,"clear":clear}

def decide(l1_ok,l1_counterfeit,perm_bad,api_bad,clear_bad,unknown_bad):
    if l1_counterfeit:
        return "COUNTERFEIT"
    if (not l1_ok) or perm_bad or api_bad or clear_bad or unknown_bad:
        return "POTENTIAL_FRAUD"
    return "OFFICIAL"

def analyze(apk_path, kb_path):
    apk = Path(apk_path)
    kb = load_kb(kb_path)
    badging = aapt_badging(apk)
    package = badging.get("package")
    apk_hash = sha256_file(apk)
    cert = apksigner_cert_sha256(apk)
    report = {
        "package": package,
        "apk_sha256": apk_hash,
        "cert_sha256": cert,
        "bank": None,
        "layer1": {},
        "layer2": {},
        "layer3": {}
    }

    kb_entry = find_kb_entry(kb, package) if package else None
    l1_ok = False; l1_counterfeit=False; l1_notes=[]
    if not package:
        l1_counterfeit=True; l1_notes.append("Package not readable via aapt")
    elif not kb_entry:
        l1_counterfeit=True; l1_notes.append("Package not in KB whitelist")
    else:
        report["bank"] = kb_entry.get("_bank")
        # check cert if available in KB
        kb_certs = [c.lower().replace(":","").replace(" ","") for c in kb_entry.get("cert_sha256",[])]
        if cert:
            if kb_certs:
                if cert not in kb_certs:
                    l1_counterfeit=True; l1_notes.append("Signer certificate mismatch vs KB")
                else:
                    l1_ok=True; l1_notes.append("Cert matches KB")
            else:
                l1_notes.append("No cert in KB to compare; installer should fill KB")
                l1_ok = True  # act leniently if KB doesn't have cert
        else:
            l1_notes.append("apksigner not found or cert not extractable")

        # optional apk hash compare
        kb_hashes = [h.lower() for h in kb_entry.get("official_apk_sha256",[])]
        if kb_hashes:
            if apk_hash in kb_hashes:
                l1_notes.append("APK SHA256 matches KB official release")
            else:
                l1_notes.append("APK SHA256 does NOT match KB official release")

    report["layer1"]["notes"] = l1_notes

    # Layer 2: perms and static
    perms = aapt_permissions(apk)
    suspicious = sorted(list(perms & DANGEROUS_PERMS))
    report["layer2"]["permissions_all"] = sorted(list(perms))
    report["layer2"]["permissions_suspicious"] = suspicious

    # Decompile + scan
    with tempfile.TemporaryDirectory(prefix="jadx_") as td:
        ok = False
        if which("jadx"):
            ok = True
            decomp = Path(td)/"src"
            os.makedirs(decomp, exist_ok=True)
            rc,out = run([which("jadx"), "-d", str(decomp), str(apk)])
            hits = scan_sources(decomp)
        else:
            hits = {"apis": [], "urls": [], "ips": []}

    report["layer2"]["suspicious_api_hits"] = hits["apis"][:200]
    report["layer2"]["found_urls"] = hits["urls"][:400]
    report["layer2"]["found_ips"] = hits["ips"][:200]

    # Layer 3: endpoint allowlist check
    allow = set(kb_entry.get("allowed_domains",[])) if kb_entry else set()
    endpoint_eval = filter_endpoints(report["layer2"]["found_urls"], allow)
    report["layer3"]["allowed_urls"] = endpoint_eval["allowed"]
    report["layer3"]["unknown_urls"] = endpoint_eval["unknown"]
    report["layer3"]["cleartext_urls"] = endpoint_eval["clear"]

    # Decision heuristics
    perm_bad = len(suspicious) >= 2
    api_bad = len(hits["apis"]) >= 2
    clear_bad = len(endpoint_eval["clear"]) >= 1
    unknown_bad = len(endpoint_eval["unknown"]) >= 3

    verdict = decide(l1_ok, l1_counterfeit, perm_bad, api_bad, clear_bad, unknown_bad)
    report["verdict"] = verdict
    return report

def main():
    ap = argparse.ArgumentParser(description="bank_guard3 analyzer (3-layer).")
    ap.add_argument("apk", help="APK file to analyze")
    ap.add_argument("--kb", default=KB_FILE, help="KB JSON file (default official_reference.json)")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    r = analyze(args.apk, args.kb)
    print(json.dumps(r, indent=2 if args.pretty else None, ensure_ascii=False))

if __name__ == "__main__":
    main()
