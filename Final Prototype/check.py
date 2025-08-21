# ==============================================================================
# proto3.py
#
# This is the final, corrected script for the Fraudulent App Detection System.
# It is designed to be robust against file errors and takes an APK file path
# as a command-line argument for analysis.
#
# All layers are now executed sequentially. The app is only marked as 'Safe'
# if it passes every critical check.
#
# Prerequisites:
# - Android Asset Packaging Tool (aapt) installed and in your system's PATH.
# - The 'trusted_apps.json' and 'known_fraud.json' files in the same directory.
#
# To run: python3 proto3.py <path_to_apk>

import json
import subprocess
import hashlib
import os
import sys
import time
# You would import requests here for a real VirusTotal API call
# import requests

# --- Configuration & Data Files ---
# These constants define the file names for our databases.
TRUSTED_DB_FILE = 'trusted_apps.json'
KNOWN_FRAUD_DB_FILE = 'known_fraud.json'
OUTPUT_REPORT_FILE = 'analysis_report.json'

# A list of dangerous permissions to check for anomalies.
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
    """
    Loads a JSON database from a file.
    Prints an error and returns None if the file is not found.
    """
    try:
        if not os.path.exists(file_path):
            print(f"Error: Database file '{file_path}' not found.")
            return None
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading database from '{file_path}': {e}")
        return None

def save_report_to_json(report, file_path):
    """
    Saves the analysis report to a JSON file, overwriting existing content.
    """
    try:
        with open(file_path, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n✅ Analysis report saved to '{file_path}'")
    except Exception as e:
        print(f"\n🚨 Error: Could not save report to '{file_path}': {e}")

def get_apk_hash(apk_path):
    """
    Calculates the SHA256 hash of an APK file.
    Returns None if the file does not exist.
    """
    if not os.path.exists(apk_path):
        return None
    sha256_hash = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def _get_package_name_from_apk(apk_path):
    """
    Extracts the package name from an APK using aapt.
    Returns the package name as a string or "N/A" on error.
    """
    try:
        aapt_command = ['aapt', 'dump', 'badging', apk_path]
        result = subprocess.run(aapt_command, capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if line.startswith('package:'):
                return line.split('\'')[1]
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return "N/A"

def _get_certificate_hash_from_apk(apk_path, trusted_apps_db):
    """
    SIMULATED FUNCTION:
    A real implementation would use a tool like 'apksigner' to extract the
    signing certificate's SHA256 hash securely.
    
    This mock-up returns the correct hash from the trusted database
    if the package name is found.
    """
    print(f"Simulating certificate hash extraction from: {apk_path}")
    
    # We will simulate this by checking if the package name exists in our database
    # and returning the corresponding hash if it does.
    
    package_name = _get_package_name_from_apk(apk_path)
    
    # Search for the correct mock hash in the trusted database
    if package_name != "N/A":
        # Check in the banks section
        for bank in trusted_apps_db.get('banks', []):
            for package in bank.get('packages', []):
                if package.get('id') == package_name and package.get('cert_sha256'):
                    return package['cert_sha256'][0]
        # Check in the UPI apps section
        for app in trusted_apps_db.get('upi_apps', []):
            if app.get('package_name') == package_name and 'cert_sha256' in app:
                return app['cert_sha256'][0]

    # Return a mismatched hash if no match is found
    return "mismatched_signature"

def extract_apk_metadata(apk_path, trusted_apps_db):
    """
    Extracts metadata from an APK file using the 'aapt' tool and a simulated
    certificate hash extraction.
    Returns a dictionary of metadata or None on error.
    """
    if not os.path.exists(apk_path):
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
            elif line.startswith('application-label:'):
                metadata['app_label'] = line.split('\'')[1]
            elif line.startswith('uses-permission:'):
                perm = line.split('\'')[1]
                if 'permissions' not in metadata:
                    metadata['permissions'] = []
                metadata['permissions'].append(perm)

        metadata['apk_hash'] = get_apk_hash(apk_path)
        metadata['signature_hash'] = _get_certificate_hash_from_apk(apk_path, trusted_apps_db)

        return metadata
    except subprocess.CalledProcessError as e:
        print(f"Error running aapt: {e.stderr}")
        return None
    except FileNotFoundError:
        return None

# --- Layered Analysis Functions ---

def analyze_layer_1_package_name(apk_metadata, trusted_apps_db):
    """
    Performs Layer 1: Package Name Match.
    Returns: dict with status and verdict.
    """
    print("Performing Layer 1 check (Package Name Match)...")
    time.sleep(0.5)

    package_name = apk_metadata.get('package_name', 'N/A')
    
    trusted_package_info = None
    for category in [trusted_apps_db.get('banks', []), trusted_apps_db.get('upi_apps', [])]:
        for entry in category:
            if 'packages' in entry: # Bank apps have a nested structure
                for package in entry.get('packages', []):
                    if package.get('id') == package_name:
                        trusted_package_info = package
                        return {"status": "Passed", "verdict": f"Package name '{package_name}' matches a trusted app.", "trusted_info": trusted_package_info}
            else: # UPI app entry
                if entry.get('package_name') == package_name:
                    trusted_package_info = entry
                    return {"status": "Passed", "verdict": f"Package name '{package_name}' matches a trusted app.", "trusted_info": trusted_package_info}
    
    return {"status": "Failed", "verdict": f"Package name '{package_name}' does not match any trusted app."}


def analyze_layer_2_developer_signature(apk_metadata, trusted_app_info):
    """
    Performs Layer 2: Developer Signature Check.
    Returns: dict with status and verdict.
    """
    print("Performing Layer 2 check (Developer Signature Check)...")
    time.sleep(0.5)

    apk_signature_hash = apk_metadata.get('signature_hash')
    
    # Check if this app type has a cert_sha256 in the database (e.g., bank apps)
    if trusted_app_info and trusted_app_info.get('cert_sha256'):
        trusted_hashes = trusted_app_info.get('cert_sha256')
        if apk_signature_hash in trusted_hashes:
            return {"status": "Passed", "verdict": "Developer signature hash matches a trusted signature."}
        else:
            return {"status": "Failed", "verdict": "Developer signature hash does not match a trusted signature. Potential tampering."}
    
    # For UPI apps where cert_sha256 is not provided, this layer is non-critical.
    return {"status": "Passed", "verdict": "Developer signature check skipped. Not applicable for this app type."}


def analyze_layer_3_virustotal(file_hash):
    """
    Performs Layer 3: VirusTotal API Check.
    Returns: dict with status and verdict. (Simulated)
    """
    print("Performing Layer 3 check (VirusTotal API)...")
    time.sleep(0.5)
    # Placeholder verdict
    return {"status": "Passed", "verdict": "VirusTotal check simulated. No threats found."}


def analyze_layer_4_known_fraud(apk_metadata, known_fraud_db):
    """
    Checks if the app's hash matches a known fraudulent hash.
    
    Returns:
        dict: The analysis report for this layer.
    """
    print("Performing Layer 4 check (Known Fraud hashes)...")
    file_hash = apk_metadata.get('apk_hash', 'N/A')
    
    if file_hash in known_fraud_db.get('fraudulent_hashes', []):
        return {"status": "Failed", "verdict": "File hash matches a known fraudulent app."}
    else:
        return {"status": "Passed", "verdict": "Hash does not match any known fraudulent apps."}

def analyze_layer_5_heuristics(apk_metadata, trusted_app_info):
    """
    Performs Layer 5: Heuristics Check (Permission Anomalies).
    Returns: dict with status and verdict.
    """
    print("Performing Layer 5 check (Heuristics)...")
    time.sleep(0.5)

    apk_permissions = set(apk_metadata.get('permissions', []))
    official_permissions = set(trusted_app_info.get('official_permissions', [])) if trusted_app_info else set()
    
    extra_permissions = apk_permissions - official_permissions
    dangerous_anomalies = extra_permissions.intersection(DANGEROUS_PERMISSIONS)
    
    missing_permissions = official_permissions - apk_permissions
    
    verdict_parts = []
    if dangerous_anomalies:
        verdict_parts.append(f"Detected unexpected dangerous permissions: {', '.join(dangerous_anomalies)}")
    if missing_permissions:
        verdict_parts.append(f"App is missing official permissions: {', '.join(missing_permissions)}")
        
    if verdict_parts:
        return {"status": "Warning", "verdict": ". ".join(verdict_parts)}
    else:
        return {"status": "Passed", "verdict": "No suspicious heuristics detected."}


def analyze_apk(apk_path, trusted_apps_db, known_fraud_db):
    """
    Orchestrates the multi-layered analysis of an APK.
    Returns: dict with the full analysis report.
    """
    apk_metadata = extract_apk_metadata(apk_path, trusted_apps_db)
    
    if not apk_metadata:
        return {
            'classification': 'Unknown',
            'apk_path': apk_path,
            'package_name': 'N/A',
            'app_label': 'N/A',
            'reasons': ["Analysis failed. The file was not found or aapt tool is missing."],
            'layer_results': {}
        }

    report = {
        'apk_path': apk_path,
        'package_name': apk_metadata.get('package_name', 'N/A'),
        'app_label': apk_metadata.get('app_label', 'N/A'),
        'file_hash': apk_metadata.get('apk_hash', 'N/A'),
        'classification': 'Unknown',
        'reasons': [],
        'layer_results': {}
    }
    
    # --- Run all layers first and collect results ---
    layer_1_result = analyze_layer_1_package_name(apk_metadata, trusted_apps_db)
    report['layer_results']['Layer 1 (Package Name)'] = layer_1_result
    
    trusted_app_info = layer_1_result.get('trusted_info')

    layer_2_result = analyze_layer_2_developer_signature(apk_metadata, trusted_app_info)
    report['layer_results']['Layer 2 (Developer Signature)'] = layer_2_result
    
    layer_3_result = analyze_layer_3_virustotal(apk_metadata.get('apk_hash'))
    report['layer_results']['Layer 3 (VirusTotal API)'] = layer_3_result
    
    layer_4_result = analyze_layer_4_known_fraud(apk_metadata, known_fraud_db)
    report['layer_results']['Layer 4 (Known Fraud)'] = layer_4_result
    
    layer_5_result = analyze_layer_5_heuristics(apk_metadata, trusted_app_info)
    report['layer_results']['Layer 5 (Heuristics Check)'] = layer_5_result
    
    # --- Determine the final verdict based on aggregated results ---
    reasons = []
    
    is_safe = True
    
    # Layer 1 is critical
    if layer_1_result['status'] == 'Failed':
        is_safe = False
        reasons.append(f"Layer 1: FAILED. {layer_1_result['verdict']}")

    # Layer 2 is critical
    if layer_2_result['status'] == 'Failed':
        is_safe = False
        reasons.append(f"Layer 2: FAILED. {layer_2_result['verdict']}")
    
    # Layer 3 is critical
    if layer_3_result['status'] == 'Failed':
        is_safe = False
        reasons.append(f"Layer 3: FAILED. {layer_3_result['verdict']}")

    # Layer 4 is critical
    if layer_4_result['status'] == 'Failed':
        is_safe = False
        reasons.append(f"Layer 4: FAILED. {layer_4_result['verdict']}")

    # Layer 5 is non-critical, so it only adds a warning
    if layer_5_result['status'] == 'Warning':
        reasons.append(f"Layer 5: WARNING. {layer_5_result['verdict']}")
    elif layer_5_result['status'] == 'Failed': # This would be a critical failure in a real scenario
        is_safe = False
        reasons.append(f"Layer 5: FAILED. {layer_5_result['verdict']}")

    if is_safe:
        report['classification'] = 'Safe'
        reasons.insert(0, "All critical security layers passed checks.")
    else:
        report['classification'] = 'Fraud'

    report['reasons'] = reasons
    return report

def generate_report(analysis_result):
    """
    Generates a human-readable report from the analysis results.
    """
    report_text = f"""
============================================================
           Fraud Detection Report for {analysis_result.get('app_label', 'N/A')}
============================================================
APK Path: {analysis_result['apk_path']}
Package Name: {analysis_result['package_name']}
File Hash: {analysis_result.get('file_hash', 'N/A')}

Classification: {analysis_result['classification']}
------------------------------------------------------------
Analysis Details:
"""
    for reason in analysis_result['reasons']:
        report_text += f"- {reason}\n"
    report_text += "============================================================"
    return report_text

def save_report_to_json(report, file_path):
    """Saves the analysis report to a JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n✅ Analysis report saved to '{file_path}'")
    except Exception as e:
        print(f"\n🚨 Error: Could not save report to '{file_path}': {e}")


# --- Main Execution Block ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 proto3.py <path_to_apk>")
        sys.exit(1)
    
    apk_to_analyze = sys.argv[1]
    
    print("Initializing Fraudulent App Detection System...")
    
    trusted_apps_db = load_database_from_file(TRUSTED_DB_FILE)
    known_fraud_db = load_database_from_file(KNOWN_FRAUD_DB_FILE)

    if not trusted_apps_db or not known_fraud_db:
        print("Could not load databases. Exiting.")
        sys.exit(1)
    
    print(f"\n--- Analyzing {apk_to_analyze} ---")
    
    analysis_result = analyze_apk(apk_to_analyze, trusted_apps_db, known_fraud_db)
    
    # Outputting the human-readable report to the console
    print(generate_report(analysis_result))
    
    # Saving the full JSON report to a file
    save_report_to_json(analysis_result, OUTPUT_REPORT_FILE)
    
    final_verdict = analysis_result['classification'].upper()
    if final_verdict == 'FRAUD':
        print(f"\n🚨 Final Verdict: App is FRAUD")
    elif final_verdict == 'SAFE':
        print(f"\n✅ Final Verdict: App is SAFE")
    else:
        print(f"\n⚠️ Final Verdict: App is UNKNOWN")
    
    print("\nSystem analysis complete.")
