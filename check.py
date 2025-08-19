#!/usr/bin/env python3
"""
bank_guard.py — classify an Android APK as OFFICIAL vs POTENTIAL_FRAUD
Rule v1: whitelist by package name (from official Play Store listings)
Optional v2 (recommended): also verify signing cert SHA-256.
"""

import argparse, json, subprocess, tempfile, os, sys, shutil

# === Whitelist of official Android package names per bank ===
OFFICIAL_BANK_APPS = {
    "State Bank of India (SBI)": {
        "com.sbi.lotusintouch",     # YONO SBI (Banking & Lifestyle)
        "com.sbi.SBIFreedomPlus",   # YONO Lite SBI
    },  # sources: Play Store pages. 
    "HDFC Bank": {
        "com.snapwork.hdfc",        # HDFC Bank MobileBanking
        "com.hdfc.cbx",             # HDFC Bank Corp Mobile
    },
    "ICICI Bank": {
        "com.csam.icici.bank.imobile",  # iMobile / iMobile Pay
    },
    "Axis Bank": {
        "com.axis.mobile"           # Axis Mobile
    },
    "Kotak Mahindra Bank": {
        "com.kotak.bank.mobile"     # Kotak Mobile Banking
    },
    "Punjab National Bank (PNB)": {
        "com.Version1"              # PNB ONE
    },
    "Bank of Baroda": {
        "com.bankofbaroda.mconnect" # bob World
    },
    "Canara Bank": {
        "com.canarabank.mobility"   # Canara ai1
    },
    "Union Bank of India": {
        "com.infrasoft.uboi"        # Vyom
    },
    "IDFC FIRST Bank": {
        "com.idfcfirstbank.optimus" # IDFC FIRST Bank: MobileBanking
    },
    "IndusInd Bank": {
        "com.fss.indus",            # IndusMobile (legacy/retained)
        "com.indusind.indie",       # INDIE (new retail app)
    },
    "Federal Bank": {
        "com.fedmobile"             # FedMobile
    },
    "Bank of India": {
        "com.boi.ua.android"        # BOI Mobile
    },
    "Indian Bank": {
        "com.iexceed.ib.digitalbankingprod"  # IndSMART (successor to IndOASIS)
    },
    "IDBI Bank": {
        "com.snapwork.IDBI"         # IDBI GO Mobile+
    },
    "UCO Bank": {
        "com.lcode.ucomobilebanking" # UCO mBanking Plus
    },
    "Central Bank of India": {
        "com.infrasofttech.CentralBank" # Cent Mobile
    },
    "Bank of Maharashtra": {
        "com.kiya.mahaplus"         # Mahamobile Plus
    },
    "YES BANK": {
        "in.irisbyyes.app"          # IRIS by YES BANK
    },
    "RBL Bank": {
        "com.rblbank.mobank"        # RBL MyBank (prev. MoBank)
    },
}

def aapt_dump_badging(apk_path: str) -> dict:
    """Extract package name and certificate digest using aapt/aapt2 and apksigner if available."""
    # Get package name
    try:
        out = subprocess.check_output(["aapt", "dump", "badging", apk_path], text=True, stderr=subprocess.STDOUT)
    except Exception:
        out = subprocess.check_output(["aapt2", "dump", "badging", apk_path], text=True, stderr=subprocess.STDOUT)
    pkg = None
    for line in out.splitlines():
        if line.startswith("package:"):
            # e.g., package: name='com.example' versionCode='1' versionName='1.0'
            parts = line.split()
            for p in parts:
                if p.startswith("name="):
                    pkg = p.split("=",1)[1].strip("'\"")
                    break
            break

    # Optional: signer cert digest (requires build-tools 'apksigner')
    cert_sha256 = None
    try:
        sig = subprocess.check_output(["apksigner", "verify", "--print-certs", apk_path], text=True, stderr=subprocess.STDOUT)
        for line in sig.splitlines():
            if "Signer #1 certificate SHA-256 digest:" in line:
                cert_sha256 = line.split(":",1)[1].strip().replace(" ", "").lower()
                break
    except Exception:
        pass

    return {"package": pkg, "cert_sha256": cert_sha256}

def classify(apk_path: str, official_map=OFFICIAL_BANK_APPS, trusted_certs=None):
    meta = aapt_dump_badging(apk_path)
    pkg = meta["package"]
    cert = meta["cert_sha256"]

    verdict = "POTENTIAL_FRAUD"
    reasons = []
    matched_bank = None

    # Rule 1: package whitelist
    for bank, pkgs in official_map.items():
        if pkg in pkgs:
            matched_bank = bank
            verdict = "OFFICIAL"
            reasons.append(f"Package '{pkg}' is in the official whitelist for {bank}.")
            break

    # Rule 2 (optional stronger): signer cert must match known cert for that package
    # Provide a mapping like {"com.sbi.lotusintouch": {"sha256": {"<digest1>", "<digest2>"}}}
    if trusted_certs and pkg in trusted_certs:
        expected = {d.lower().replace(":", "").replace(" ", "") for d in trusted_certs[pkg].get("sha256", [])}
        if cert is None:
            verdict = "POTENTIAL_FRAUD"
            reasons.append("Missing cert digest; cannot validate signing identity.")
        elif cert not in expected:
            verdict = "POTENTIAL_FRAUD"
            reasons.append(f"Signer digest {cert} does not match known official digests for {pkg}.")
        else:
            reasons.append("Signer digest matches known official certificate.")

    return {
        "verdict": verdict,
        "apk_package": pkg,
        "bank": matched_bank,
        "cert_sha256": cert,
        "notes": reasons,
    }

def main():
    ap = argparse.ArgumentParser(description="Classify banking APK as OFFICIAL or POTENTIAL_FRAUD")
    ap.add_argument("apk", help="Path to APK")
    ap.add_argument("--certs-json", help="(Optional) JSON file mapping package-> {sha256: [..]}")
    args = ap.parse_args()

    trusted = None
    if args.certs_json:
        with open(args.certs_json, "r", encoding="utf-8") as f:
            trusted = json.load(f)

    result = classify(args.apk, OFFICIAL_BANK_APPS, trusted_certs=trusted)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
