import logging
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

# Configure logging
logger = logging.getLogger(__name__)

# Lazy-loaded configuration (loaded on first request or explicit init)
_config = None
REQUESTS_TIMEOUT = 60


class AnalyzeAPIError(Exception):
    """Exception for Spectra Analyze API errors."""

    def __init__(self, message: str, status_code: int = 500, user_message: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.user_message = user_message or message


# HTTP error code mappings for user-friendly messages
UPLOAD_ERROR_MESSAGES = {
    400: "Invalid request. Please check the file and try again.",
    403: "Authentication failed. Please contact the administrator.",
    405: "The analysis service is currently in maintenance mode. Please try again later.",
    413: "File size exceeds the maximum allowed limit.",
    429: "System resources are currently depleted. Please try again later.",
    503: "Disk storage limit exceeded. Please contact the administrator.",
}

STATUS_ERROR_MESSAGES = {
    404: "Status check failed due to validation error.",
}

CLASSIFICATION_ERROR_MESSAGES = {
    403: "Authentication failed. Please contact the administrator.",
    404: "Hash not found in database.",
    429: "Daily query limit reached. Please try again tomorrow.",
    503: "Classification service is currently unavailable.",
}


def _make_api_request(method, url, error_messages, **kwargs):
    """
    Make an API request with comprehensive error handling.

    Args:
        method: HTTP method ('get', 'post')
        url: Request URL
        error_messages: Dict mapping status codes to user-friendly messages
        **kwargs: Additional arguments for requests

    Returns:
        Tuple of (status_code, response_body)

    Raises:
        AnalyzeAPIError: On network errors, JSON parse errors, or HTTP errors
    """
    try:
        if method == "get":
            resp = requests.get(url, timeout=REQUESTS_TIMEOUT, **kwargs)
        elif method == "post":
            resp = requests.post(url, timeout=REQUESTS_TIMEOUT, **kwargs)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
    except requests.Timeout as e:
        logger.error(f"Request timeout for {url}: {e}")
        raise AnalyzeAPIError(
            f"Request timeout: {e}",
            status_code=504,
            user_message="The request timed out. Please try again.",
        )
    except requests.ConnectionError as e:
        logger.error(f"Connection error for {url}: {e}")
        raise AnalyzeAPIError(
            f"Connection error: {e}",
            status_code=503,
            user_message="Unable to connect to the analysis service. Please try again later.",
        )
    except requests.RequestException as e:
        logger.error(f"Request failed for {url}: {e}")
        raise AnalyzeAPIError(
            f"Request failed: {e}",
            status_code=500,
            user_message="An unexpected error occurred while contacting the analysis service.",
        )

    # Handle non-success status codes
    if resp.status_code not in (200, 201):
        user_message = error_messages.get(resp.status_code, f"API error (HTTP {resp.status_code})")
        logger.warning(f"API error {resp.status_code} for {url}: {resp.text[:200]}")
        raise AnalyzeAPIError(
            f"HTTP {resp.status_code}: {resp.text[:200]}",
            status_code=resp.status_code,
            user_message=user_message,
        )

    # Parse JSON response
    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Invalid JSON response from {url}: {e}")
        raise AnalyzeAPIError(
            f"Invalid JSON response: {e}",
            status_code=502,
            user_message="Received an invalid response from the analysis service.",
        )

    return resp.status_code, body


def _parse_classification_response(body, hash_value):
    """
    Parse and validate a classification response.

    Args:
        body: Response body dict
        hash_value: The hash that was queried

    Returns:
        Dict with classification data

    Raises:
        AnalyzeAPIError: If response indicates hash not found or invalid structure
    """
    # Check for "Hash not found" in 200 response
    if isinstance(body, dict) and body.get("message") == "Hash not found.":
        raise AnalyzeAPIError(
            f"Hash not found: {hash_value}",
            status_code=404,
            user_message="Hash not found in database.",
        )

    # Validate expected structure
    if not isinstance(body, dict):
        raise AnalyzeAPIError(
            "Unexpected response structure",
            status_code=502,
            user_message="Received an unexpected response format from the analysis service.",
        )

    return {
        "classification": body.get("classification", "Unknown"),
        "md5": body.get("md5"),
        "sha1": body.get("sha1"),
        "sha256": body.get("sha256"),
    }


def _extract_sample_status(body):
    """
    Safely extract sample status from status response.

    Args:
        body: Response body dict

    Returns:
        Status string or None if unable to extract

    Raises:
        AnalyzeAPIError: If response structure is invalid
    """
    if not isinstance(body, dict):
        raise AnalyzeAPIError(
            "Invalid status response structure",
            status_code=502,
            user_message="Received an invalid status response.",
        )

    results = body.get("results")
    if not isinstance(results, list) or len(results) == 0:
        raise AnalyzeAPIError(
            "Empty or invalid results in status response",
            status_code=502,
            user_message="Received an empty status response.",
        )

    first_result = results[0]
    if not isinstance(first_result, dict):
        raise AnalyzeAPIError(
            "Invalid result structure in status response",
            status_code=502,
            user_message="Received an invalid status response format.",
        )

    return first_result.get("status")


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
        return jsonify(success=False, message="File and email are required"), 400

    filename = secure_filename(infile.filename)
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    infile.save(temp_path)

    headers = {"Authorization": f"Token {_api_token()}"}

    # Upload file to Spectra Analyze
    try:
        file_handle = open(temp_path, "rb")
        files = {"file": (filename, file_handle)}
        data = {"comment": email, "analysis": json.dumps({"cloud": True})}

        try:
            _, body = _make_api_request(
                "post",
                _submit_url(),
                UPLOAD_ERROR_MESSAGES,
                files=files,
                data=data,
                headers=headers,
                verify=_ssl_verify(),
            )
        finally:
            file_handle.close()
    except AnalyzeAPIError as e:
        logger.error(f"File upload failed: {e}")
        return jsonify(success=False, message=e.user_message), e.status_code
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # Extract SHA1 from upload response
    detail = body.get("detail")
    if not isinstance(detail, dict):
        logger.error("Invalid upload response structure: missing detail")
        return jsonify(
            success=False,
            message="Received an invalid response from the upload service.",
        ), 502

    sha1 = detail.get("sha1")
    if not sha1:
        logger.error("Invalid upload response structure: missing sha1 in detail")
        return jsonify(
            success=False,
            message="Received an invalid response from the upload service (missing hash).",
        ), 502

    # Poll for processing completion with error handling
    status = "pending"
    timeout = 600  # seconds
    interval = 5
    elapsed = 0
    max_consecutive_errors = 3
    consecutive_errors = 0

    while elapsed < timeout:
        try:
            _, status_body = _make_api_request(
                "post",
                _status_url(),
                STATUS_ERROR_MESSAGES,
                json={"hash_values": [sha1]},
                headers=headers,
                verify=_ssl_verify(),
            )
            # Reset error counter on success
            consecutive_errors = 0

            status = _extract_sample_status(status_body)
            if status == "processed":
                break

        except AnalyzeAPIError as e:
            consecutive_errors += 1
            logger.warning(
                f"Status poll error ({consecutive_errors}/{max_consecutive_errors}): {e}"
            )
            if consecutive_errors >= max_consecutive_errors:
                logger.error(
                    f"Status polling failed after {max_consecutive_errors} consecutive errors"
                )
                return jsonify(
                    success=False,
                    message="Unable to check processing status. Please try looking up the file later.",
                ), 503

        time.sleep(interval)
        elapsed += interval

    if status != "processed":
        return jsonify(
            success=False,
            message="File submitted but processing timed out. Please try looking up the file later.",
            sha1=sha1,
        ), 202

    # Fetch classification (using v3 endpoint)
    try:
        _, classification_body = _make_api_request(
            "get",
            f"{_classification_url()}{sha1}/classification/",
            CLASSIFICATION_ERROR_MESSAGES,
            headers=headers,
            verify=_ssl_verify(),
        )
        classification_data = _parse_classification_response(classification_body, sha1)
    except AnalyzeAPIError as e:
        logger.error(f"Classification fetch failed after upload: {e}")
        return jsonify(
            success=False,
            message="Processing complete, but failed to retrieve classification.",
            sha1=sha1,
        ), 500

    return jsonify(
        success=True,
        classification=classification_data["classification"],
        md5=classification_data["md5"],
        sha1=classification_data["sha1"],
        sha256=classification_data["sha256"],
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
        _, body = _make_api_request(
            "get",
            f"{_classification_url()}{hash_value}/classification/",
            CLASSIFICATION_ERROR_MESSAGES,
            headers=headers,
            verify=_ssl_verify(),
        )
        classification_data = _parse_classification_response(body, hash_value)
    except AnalyzeAPIError as e:
        logger.warning(f"Lookup failed for hash {hash_value}: {e}")
        return jsonify(success=False, message=e.user_message), e.status_code

    return jsonify(
        success=True,
        classification=classification_data["classification"],
        md5=classification_data["md5"],
        sha1=classification_data["sha1"],
        sha256=classification_data["sha256"],
        message="Hash lookup successful",
    )
