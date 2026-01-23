import os
import json
import re
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
CLASSIFICATION_URL = f"{API_BASE}/api/samples/v3/"
REQUESTS_TIMEOUT = 60
ANALYZE_SSL_VERIFY = os.getenv("ANALYZE_SSL_VERIFY", "true").lower() == "true"

# Hash validation patterns
HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
}


def validate_hash(hash_value):
    """Validate a hash string and return its type, or None if invalid."""
    if not hash_value or not isinstance(hash_value, str):
        return None
    hash_value = hash_value.strip()
    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(hash_value):
            return hash_type
    return None


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
        resp = requests.post(SUBMIT_URL, files=files, data=data, headers=headers, timeout=60, verify=ANALYZE_SSL_VERIFY)
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
            STATUS_URL, json={"hash_values": [sha1]}, headers=headers, timeout=REQUESTS_TIMEOUT, verify=ANALYZE_SSL_VERIFY
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

    # Fetch classification (using v3 endpoint)
    classification_resp = requests.get(
        f"{CLASSIFICATION_URL}{sha1}/classification/",
        headers=headers,
        timeout=REQUESTS_TIMEOUT,
        verify=ANALYZE_SSL_VERIFY,
    )
    if classification_resp.status_code != 200:
        return jsonify(
            success=False, message="Processing complete, but failed to get classification"
        ), 500

    classification_data = classification_resp.json()
    classification = classification_data.get("classification", "Could not find classification")
    md5 = classification_data.get("md5")
    sha1_hash = classification_data.get("sha1")
    sha256 = classification_data.get("sha256")

    return jsonify(
        success=True,
        classification=classification,
        md5=md5,
        sha1=sha1_hash,
        sha256=sha256,
        message="File analyzed successfully",
    )


@app.route("/lookup", methods=["POST"])
def lookup():
    data = request.get_json() or {}
    hash_value = data.get("hash_value", "").strip()

    if not hash_value:
        return jsonify(success=False, message="Hash value is required"), 400

    hash_type = validate_hash(hash_value)
    if not hash_type:
        return (
            jsonify(
                success=False,
                message="Invalid hash format. Provide MD5, SHA-1, SHA-256, or SHA-512.",
            ),
            400,
        )

    if not API_BASE or not API_TOKEN:
        return jsonify(success=False, message="API_BASE or API_TOKEN not set"), 500

    headers = {"Authorization": f"Token {API_TOKEN}"}

    try:
        classification_resp = requests.get(
            f"{CLASSIFICATION_URL}{hash_value}/classification/",
            headers=headers,
            timeout=REQUESTS_TIMEOUT,
            verify=ANALYZE_SSL_VERIFY,
        )
    except requests.RequestException as e:
        return jsonify(success=False, message=f"API request failed: {e}"), 500

    if classification_resp.status_code == 404:
        return jsonify(success=False, message="Hash not found in database"), 404

    if classification_resp.status_code != 200:
        return (
            jsonify(
                success=False,
                message=f"API error: {classification_resp.status_code}",
            ),
            classification_resp.status_code,
        )

    classification_data = classification_resp.json()
    classification = classification_data.get("classification", "Unknown")
    md5 = classification_data.get("md5")
    sha1 = classification_data.get("sha1")
    sha256 = classification_data.get("sha256")

    return jsonify(
        success=True,
        classification=classification,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        message="Hash lookup successful",
    )
