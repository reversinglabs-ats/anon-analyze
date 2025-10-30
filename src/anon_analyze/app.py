import os
import json
import time
import requests
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

if os.getenv("FLASK_ENV") == "development":
    from dotenv import load_dotenv

    load_dotenv()

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

API_TOKEN = os.getenv("ANALYZE_API_TOKEN")
API_BASE = os.getenv("ANALYZE_API_BASE")  # e.g. https://your.appliance.com
SUBMIT_URL = f"{API_BASE}/api/submit/file/"
STATUS_URL = f"{API_BASE}/api/samples/status/"
SUMMARY_URL = f"{API_BASE}/api/samples/v2/list/"
REQUESTS_TIMEOUT = 60


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files or "email" not in request.form:
        return jsonify(success=False, message="Missing file or email"), 400

    if not API_BASE or not API_TOKEN:
        return jsonify(success=False, message="API_BASE or API_TOKEN not set")

    infile = request.files["file"]
    email = request.form["email"]
    if infile.filename == "" or not email:
        return jsonify(success=False, message="File and email are required"), 500

    filename = secure_filename(infile.filename)
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    infile.save(temp_path)

    files = {"file": (filename, open(temp_path, "rb"))}
    data = {"comment": email, "analysis": json.dumps({"cloud": True})}
    headers = {"Authorization": f"Token {API_TOKEN}"}

    try:
        resp = requests.post(SUBMIT_URL, files=files, data=data, headers=headers, timeout=60)
    finally:
        files["file"][1].close()
        os.remove(temp_path)

    if resp.status_code not in (200, 201):
        return jsonify(success=False, message=f"{resp.status_code}: {resp.text}"), resp.status_code

    body = resp.json()
    sha1 = body.get("detail", {}).get("sha1")

    # Poll for processing completion
    status = "pending"
    timeout = 600  # seconds
    interval = 5
    elapsed = 0
    while elapsed < timeout:
        status_resp = requests.post(
            STATUS_URL, json={"hash_values": [sha1]}, headers=headers, timeout=REQUESTS_TIMEOUT
        )
        if status_resp.status_code == 200:
            status_json = status_resp.json()
            status = status_json.get("results")[0].get("status")
            if status == "processed":
                break
        time.sleep(interval)
        elapsed += interval

    if status != "processed":
        return jsonify(success=False, message="File submitted but processing timed out"), 202

    # Fetch classification
    summary_resp = requests.post(
        SUMMARY_URL, json={"hash_values": [sha1]}, headers=headers, timeout=REQUESTS_TIMEOUT
    )
    if summary_resp.status_code != 200:
        return jsonify(success=False, message="Processing complete, but failed to get summary"), 500

    summary = summary_resp.json()
    # classification = summary.get('classification', 'Unknown')
    classification = summary.get("results")[0].get(
        "classification", "Could not find classification"
    )
    return jsonify(
        success=True, classification=classification, sha1=sha1, message="File analyzed successfully"
    )
