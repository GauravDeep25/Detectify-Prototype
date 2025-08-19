# proto2.py
#
# This script is a Fraudulent Banking & UPI App Detection System.
# It reads trusted app data from a separate JSON file, analyzes an APK
# provided via the command line, and provides a structured report.
#
# Prerequisites:
# - Android Asset Packaging Tool (aapt) must be installed and in your PATH.
# - The 'trusted_apps.json' file must be in the same directory.
#
# To run: python3 proto2.py <path_to_apk>

import json
import subprocess
import hashlib
import os
import sys

# --- Configuration & Data Files ---
# The database content is now loaded from these external files.

TRUSTED_DB_FILE = 'trusted_apps.json'
KNOWN_FRAUD_DB_FILE = 'known_fraud.json'

# Dangerous permissions to look for in Layer 2
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.SEND_SMS',
    'android.permission.CALL_PHONE',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.SYSTEM_ALERT_WINDOW'
}

# --- Helper Functions ---

def load_database_from_file(file_path):
    """Loads a JSON database from a file."""
    try:
        if not os.path.exists(file_path):
            print(f"Error: Database file '{file_path}' not found.")
            print("Please ensure this file is present in the same directory as the script.")
            return None
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading database from '{file_path}': {e}")
        return None

def get_apk_hash(apk_path):
    """Calculates the SHA256 hash of an APK file."""
    if not os.path.exists(apk_path):
        return None
    sha256_hash = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return "sha256:" + sha256_hash.hexdigest()

def _get_certificate_hash_from_apk(apk_path):
    """
    SIMULATED FUNCTION:
    A real implementation would use a tool like 'apksigner' or a dedicated
    library to extract the signing certificate's SHA256 hash.
    
    This mock-up simply returns a hash based on the input string to
    demonstrate the logic. In a live system, this would be a real, verifiable hash.
    """
    print(f"Simulating certificate hash extraction from: {apk_path}")
    
    # This mock-up returns a consistent hash for a specific package name,
    # and a different one for others, to demonstrate the logic.
    mock_hashes = {
        "com.sbi.lotusintouch": "d8a23e4b7c6c4f3d1e2a8b9f1d0a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2b"
    }
    
    # We'll need a way to get the package name without aapt for this mock function
    # In a real tool, this would be a single process.
    if 'sbi' in apk_path.lower(): # Simple heuristic for the mock
        return mock_hashes.get("com.sbi.lotusintouch")
        
    return hashlib.sha256(apk_path.encode('utf-8')).hexdigest()


def extract_apk_metadata(apk_path):
    """
    Extracts metadata from an APK file using the 'aapt' tool and a simulated
    certificate hash extraction.
    Returns a dictionary of metadata or None on error.
    """
    if not os.path.exists(apk_path):
        print(f"Error: APK file not found at '{apk_path}'")
        return None

    try:
        aapt_command = ['aapt', 'dump', 'badging', apk_path]
        result = subprocess.run(aapt_command, capture_output=True, text=True, check=True)
        output = result.stdout
        
        metadata = {}
        for line in output.splitlines():
            if line.startswith('package:'):
                parts = line.split('\'')
                metadata['package_name'] = parts[1]
                metadata['version_code'] = parts[3]
                metadata['version_name'] = parts[5]
            elif line.startswith('application-label:'):
                metadata['app_label'] = line.split('\'')[1]
            elif line.startswith('uses-permission:'):
                perm = line.split('\'')[1]
                if 'permissions' not in metadata:
                    metadata['permissions'] = []
                metadata['permissions'].append(perm)

        metadata['apk_hash'] = get_apk_hash(apk_path)
        metadata['signature_hash'] = _get_certificate_hash_from_apk(apk_path)

        return metadata
    except subprocess.CalledProcessError as e:
        print(f"Error running aapt: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: 'aapt' command not found. Please ensure Android SDK Platform-Tools is installed and in your PATH.")
        return None

def analyze_apk(apk_path, trusted_apps_db, known_fraud_db):
    """
    Performs a three-layer verification on an APK file.
    Returns a dictionary with classification and reasons.
    """
    apk_metadata = extract_apk_metadata(apk_path)
    if not apk_metadata:
        return {
            'classification': 'Unknown', 
            'apk_path': apk_path,
            'package_name': 'N/A',
            'app_label': 'N/A',
            'reasons': [f"Failed to analyze APK. The file '{apk_path}' was not found or aapt tool is missing."]
        }

    report = {
        'apk_path': apk_path,
        'package_name': apk_metadata.get('package_name', 'N/A'),
        'app_label': apk_metadata.get('app_label', 'N/A'),
        'classification': 'Fraud',  # Assume fraud until proven safe
        'reasons': []
    }
    
    trusted_package_info = None

    # --- Layer 1: Package Name + Signature Check ---
    package_match_found = False
    for category in [trusted_apps_db.get('banks', []), trusted_apps_db.get('upi_apps', [])]:
        for entry in category:
            for package in entry.get('packages', []):
                if apk_metadata.get('package_name') == package.get('id'):
                    trusted_package_info = package
                    report['reasons'].append(f"Layer 1: Package name '{package['id']}' matches a trusted app.")
                    package_match_found = True
                    break
            if package_match_found: break
        if package_match_found: break

    if package_match_found:
        if 'signature_hash' in apk_metadata and trusted_package_info['cert_sha256'] and apk_metadata['signature_hash'] in trusted_package_info['cert_sha256']:
            report['classification'] = 'Safe'
            report['reasons'].append("Layer 1: Developer signature hash matches. App is considered Safe.")
            return report
        else:
            report['reasons'].append("Layer 1: FAILED. Developer signature hash does not match a trusted signature. Proceeding to next layers.")
    else:
        report['reasons'].append("Layer 1: FAILED. Package name does not match any trusted app.")
        report['reasons'].append("Skipping Layer 2 due to no official permissions data for an unknown app.")

    # --- Layer 2: Permission Anomaly Detection ---
    if trusted_package_info and 'official_permissions' in trusted_package_info and trusted_package_info['official_permissions']:
        apk_permissions = set(apk_metadata.get('permissions', []))
        official_permissions = set(trusted_package_info['official_permissions'])
        
        extra_permissions = apk_permissions - official_permissions
        dangerous_anomalies = extra_permissions.intersection(DANGEROUS_PERMISSIONS)

        if dangerous_anomalies:
            report['reasons'].append(f"Layer 2: FAILED. Detected dangerous and unexpected permissions: {', '.join(dangerous_anomalies)}")
        else:
            report['reasons'].append("Layer 2: Passed. No dangerous permission anomalies detected.")
    else:
        report['reasons'].append("Layer 2: Could not perform checks because official permission data is missing.")
        
    # --- Layer 3: Heuristic & Hash-based Detection ---
    report['reasons'].append("Layer 3: Performing heuristic and hash-based checks.")
    apk_hash = apk_metadata.get('apk_hash', 'N/A')
    if apk_hash in known_fraud_db['fraudulent_hashes']:
        report['reasons'].append("Layer 3: FAILED. APK hash matches a known fraudulent sample in the database.")
    else:
        report['reasons'].append("Layer 3: Passed. APK hash does not match a known fraudulent sample.")

    return report


def generate_report(analysis_result):
    """
    Generates a human-readable report from the analysis results.
    """
    if analysis_result is None:
        return "Error: Analysis failed due to missing APK file."

    report_text = f"""
============================================================
           Fraud Detection Report for {analysis_result.get('app_label', 'N/A')}
============================================================
APK Path: {analysis_result['apk_path']}
Package Name: {analysis_result['package_name']}

Classification: {analysis_result['classification']}
------------------------------------------------------------
Analysis Details:
"""
    for reason in analysis_result['reasons']:
        report_text += f"- {reason}\n"
    
    report_text += "============================================================"
    return report_text

# --- Main Execution Block ---

if __name__ == "__main__":
    # Check if a file path was provided as a command-line argument
    if len(sys.argv) < 2:
        print("Usage: python3 proto2.py <path_to_apk>")
        sys.exit(1)
    
    # Get the APK file path from the command line
    apk_to_analyze = sys.argv[1]
    
    print("Initializing Fraudulent App Detection System...")
    
    trusted_apps = load_database_from_file(TRUSTED_DB_FILE)
    known_fraud_hashes = load_database_from_file(KNOWN_FRAUD_DB_FILE)

    if not trusted_apps or not known_fraud_hashes:
        print("Could not load databases. Exiting.")
    else:
        print(f"\n--- Analyzing {apk_to_analyze} ---")
        analysis_result = analyze_apk(apk_to_analyze, trusted_apps, known_fraud_hashes)
        print(generate_report(analysis_result))
        
        print(f"\nFinal Verdict: App is {analysis_result['classification'].upper()}")
        
    print("\nSystem analysis complete.")
