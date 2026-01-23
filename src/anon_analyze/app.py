import os
import json
import re
import sys
import time
import requests
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

if os.getenv("FLASK_ENV") == "development":
    from dotenv import load_dotenv

    load_dotenv()

from anon_analyze.config import load_config, ConfigurationError

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Lazy-loaded configuration (loaded on first request or explicit init)
_config = None
REQUESTS_TIMEOUT = 60


def _get_config():
    """Get validated configuration, loading it on first access."""
    global _config
    if _config is None:
        try:
            _config = load_config()
        except ConfigurationError as e:
            sys.exit(f"Configuration error: {e}")
    return _config


def init_config():
    """Initialize configuration early (call at server startup)."""
    _get_config()


# Module-level accessors for backwards compatibility
def _api_token():
    return _get_config().api_token


def _api_base():
    return _get_config().api_base


def _submit_url():
    return _get_config().submit_url


def _status_url():
    return _get_config().status_url


def _classification_url():
    return _get_config().classification_url


def _ssl_verify():
    return _get_config().ssl_verify


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

    infile = request.files["file"]
    email = request.form["email"]
    if infile.filename == "" or not email:
        return jsonify(success=False, message="File and email are required"), 500

    filename = secure_filename(infile.filename)
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    infile.save(temp_path)

    files = {"file": (filename, open(temp_path, "rb"))}
    data = {"comment": email, "analysis": json.dumps({"cloud": True})}
    headers = {"Authorization": f"Token {_api_token()}"}

    try:
        resp = requests.post(
            _submit_url(),
            files=files,
            data=data,
            headers=headers,
            timeout=60,
            verify=_ssl_verify(),
        )
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
            _status_url(),
            json={"hash_values": [sha1]},
            headers=headers,
            timeout=REQUESTS_TIMEOUT,
            verify=_ssl_verify(),
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
        f"{_classification_url()}{sha1}/classification/",
        headers=headers,
        timeout=REQUESTS_TIMEOUT,
        verify=_ssl_verify(),
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

    headers = {"Authorization": f"Token {_api_token()}"}

    try:
        classification_resp = requests.get(
            f"{_classification_url()}{hash_value}/classification/",
            headers=headers,
            timeout=REQUESTS_TIMEOUT,
            verify=_ssl_verify(),
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
