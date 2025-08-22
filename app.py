# app.py

import os
import tempfile
import shutil
# Make sure to import render_template
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

from Test1 import analyze_apk, load_database_from_file

app = Flask(__name__)

# --- Load Databases at Startup ---
print("Loading security databases...")
TRUSTED_DB_FILE = 'trusted_apps.json'
KNOWN_FRAUD_DB_FILE = 'known_fraud.json'
trusted_apps_db = load_database_from_file(TRUSTED_DB_FILE)
known_fraud_db = load_database_from_file(KNOWN_FRAUD_DB_FILE)
print("Databases loaded successfully.")


# --- ADD THIS NEW FUNCTION ---
# This route serves the main webpage from the 'templates' folder.
@app.route('/')
def index():
    return render_template('index.html')


# --- API Backend Route ---
# This function handles the file upload and analysis.
@app.route('/analyze', methods=['POST'])
def handle_analysis():
    # (The rest of your handle_analysis function remains the same...)
    if not trusted_apps_db or not known_fraud_db:
        return jsonify({"error": "Server not configured; databases missing."}), 500

    if 'apk_file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400
    
    file = request.files['apk_file']
    if file.filename == '' or not file.filename.endswith('.apk'):
        return jsonify({"error": "No APK file selected or invalid file type."}), 400

    temp_dir = tempfile.mkdtemp()
    apk_path = os.path.join(temp_dir, secure_filename(file.filename))
    file.save(apk_path)

    try:
        analysis_result = analyze_apk(apk_path, trusted_apps_db, known_fraud_db)
        return jsonify(analysis_result)
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
    finally:
        shutil.rmtree(temp_dir)

if __name__ == '__main__':
    app.run(debug=True, port=5000)