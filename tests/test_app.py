import json
import pytest
import requests
from io import BytesIO
from unittest.mock import patch, Mock
from anon_analyze import app
from anon_analyze.app import (
    AnalyzeAPIError,
    _make_api_request,
    _parse_classification_response,
    _extract_sample_status,
)
from anon_analyze.config import AppConfig


def _mock_config():
    """Create a mock config for testing."""
    return AppConfig(
        api_token="a" * 40,
        api_base="https://test.example.com",
        ssl_verify=True,
    )


# ============================================================================
# Unit tests for helper functions
# ============================================================================


class TestAnalyzeAPIError:
    """Tests for AnalyzeAPIError exception class."""

    def test_basic_error(self):
        """Test basic exception creation."""
        err = AnalyzeAPIError("Test error")
        assert str(err) == "Test error"  # nosec B101
        assert err.status_code == 500  # nosec B101
        assert err.user_message == "Test error"  # nosec B101

    def test_custom_status_code(self):
        """Test exception with custom status code."""
        err = AnalyzeAPIError("Test error", status_code=404)
        assert err.status_code == 404  # nosec B101

    def test_custom_user_message(self):
        """Test exception with custom user message."""
        err = AnalyzeAPIError("Internal error", user_message="User friendly message")
        assert err.user_message == "User friendly message"  # nosec B101


class TestMakeApiRequest:
    """Tests for _make_api_request helper function."""

    @patch("anon_analyze.app.requests.get")
    def test_successful_get_request(self, mock_get):
        """Test successful GET request."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "test"}
        mock_get.return_value = mock_resp

        status, body = _make_api_request("get", "http://test.com", {})
        assert status == 200  # nosec B101
        assert body == {"data": "test"}  # nosec B101

    @patch("anon_analyze.app.requests.post")
    def test_successful_post_request(self, mock_post):
        """Test successful POST request."""
        mock_resp = Mock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"id": 123}
        mock_post.return_value = mock_resp

        status, body = _make_api_request("post", "http://test.com", {})
        assert status == 201  # nosec B101
        assert body == {"id": 123}  # nosec B101

    @patch("anon_analyze.app.requests.get")
    def test_timeout_error(self, mock_get):
        """Test request timeout handling."""
        mock_get.side_effect = requests.Timeout("Connection timed out")

        with pytest.raises(AnalyzeAPIError) as exc_info:
            _make_api_request("get", "http://test.com", {})

        assert exc_info.value.status_code == 504  # nosec B101
        assert "timed out" in exc_info.value.user_message.lower()  # nosec B101

    @patch("anon_analyze.app.requests.get")
    def test_connection_error(self, mock_get):
        """Test connection error handling."""
        mock_get.side_effect = requests.ConnectionError("Failed to connect")

        with pytest.raises(AnalyzeAPIError) as exc_info:
            _make_api_request("get", "http://test.com", {})

        assert exc_info.value.status_code == 503  # nosec B101
        assert "connect" in exc_info.value.user_message.lower()  # nosec B101

    @patch("anon_analyze.app.requests.get")
    def test_generic_request_exception(self, mock_get):
        """Test generic request exception handling."""
        mock_get.side_effect = requests.RequestException("Unknown error")

        with pytest.raises(AnalyzeAPIError) as exc_info:
            _make_api_request("get", "http://test.com", {})

        assert exc_info.value.status_code == 500  # nosec B101

    @patch("anon_analyze.app.requests.get")
    def test_http_error_with_custom_message(self, mock_get):
        """Test HTTP error with custom error message mapping."""
        mock_resp = Mock()
        mock_resp.status_code = 429
        mock_resp.text = "Rate limited"
        mock_get.return_value = mock_resp

        error_messages = {429: "Too many requests, please slow down."}

        with pytest.raises(AnalyzeAPIError) as exc_info:
            _make_api_request("get", "http://test.com", error_messages)

        assert exc_info.value.status_code == 429  # nosec B101
        assert exc_info.value.user_message == "Too many requests, please slow down."  # nosec B101

    @patch("anon_analyze.app.requests.get")
    def test_http_error_without_custom_message(self, mock_get):
        """Test HTTP error without custom error message mapping."""
        mock_resp = Mock()
        mock_resp.status_code = 418
        mock_resp.text = "I'm a teapot"
        mock_get.return_value = mock_resp

        with pytest.raises(AnalyzeAPIError) as exc_info:
            _make_api_request("get", "http://test.com", {})

        assert exc_info.value.status_code == 418  # nosec B101
        assert "418" in exc_info.value.user_message  # nosec B101

    @patch("anon_analyze.app.requests.get")
    def test_json_decode_error(self, mock_get):
        """Test JSON decode error handling."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_get.return_value = mock_resp

        with pytest.raises(AnalyzeAPIError) as exc_info:
            _make_api_request("get", "http://test.com", {})

        assert exc_info.value.status_code == 502  # nosec B101
        assert "invalid response" in exc_info.value.user_message.lower()  # nosec B101

    def test_unsupported_method(self):
        """Test unsupported HTTP method."""
        with pytest.raises(ValueError) as exc_info:
            _make_api_request("delete", "http://test.com", {})

        assert "Unsupported HTTP method" in str(exc_info.value)  # nosec B101


class TestParseClassificationResponse:
    """Tests for _parse_classification_response helper function."""

    def test_valid_response(self):
        """Test parsing a valid classification response."""
        body = {
            "classification": "malicious",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",  # pragma: allowlist secret
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # pragma: allowlist secret
            "sha256": "e3b0c44298fc1c149afbf4c8996fb924",  # pragma: allowlist secret
        }
        result = _parse_classification_response(body, "testhash")

        assert result["classification"] == "malicious"  # nosec B101
        assert result["md5"] == "d41d8cd98f00b204e9800998ecf8427e"  # nosec B101  # pragma: allowlist secret

    def test_hash_not_found_in_200_response(self):
        """Test detection of 'Hash not found' in 200 response."""
        body = {"message": "Hash not found.", "hash_value": "testhash"}

        with pytest.raises(AnalyzeAPIError) as exc_info:
            _parse_classification_response(body, "testhash")

        assert exc_info.value.status_code == 404  # nosec B101
        assert "not found" in exc_info.value.user_message.lower()  # nosec B101

    def test_non_dict_response(self):
        """Test handling of non-dict response."""
        with pytest.raises(AnalyzeAPIError) as exc_info:
            _parse_classification_response(["list", "data"], "testhash")

        assert exc_info.value.status_code == 502  # nosec B101

    def test_missing_classification(self):
        """Test response with missing classification defaults to Unknown."""
        body = {"md5": "d41d8cd98f00b204e9800998ecf8427e"}  # pragma: allowlist secret
        result = _parse_classification_response(body, "testhash")

        assert result["classification"] == "Unknown"  # nosec B101


class TestExtractSampleStatus:
    """Tests for _extract_sample_status helper function."""

    def test_valid_status_response(self):
        """Test extracting status from valid response."""
        body = {"results": [{"status": "processed", "sha1": "abc123"}]}
        status = _extract_sample_status(body)

        assert status == "processed"  # nosec B101

    def test_non_dict_body(self):
        """Test handling of non-dict response body."""
        with pytest.raises(AnalyzeAPIError) as exc_info:
            _extract_sample_status("not a dict")

        assert exc_info.value.status_code == 502  # nosec B101

    def test_empty_results_list(self):
        """Test handling of empty results list."""
        with pytest.raises(AnalyzeAPIError) as exc_info:
            _extract_sample_status({"results": []})

        assert exc_info.value.status_code == 502  # nosec B101

    def test_missing_results_key(self):
        """Test handling of missing results key."""
        with pytest.raises(AnalyzeAPIError) as exc_info:
            _extract_sample_status({"data": "something"})

        assert exc_info.value.status_code == 502  # nosec B101

    def test_invalid_result_structure(self):
        """Test handling of invalid result structure."""
        with pytest.raises(AnalyzeAPIError) as exc_info:
            _extract_sample_status({"results": ["not a dict"]})

        assert exc_info.value.status_code == 502  # nosec B101


# ============================================================================
# Integration tests for endpoints
# ============================================================================


def test_index_route():
    client = app.test_client()
    resp = client.get("/")
    # App renders a template; OK if 200 or 405 depending on route design
    assert resp.status_code in (200, 405)  # nosec B101


def test_health_missing_env(monkeypatch):
    client = app.test_client()
    assert app is not None  # nosec B101

    # TODO: Come back and make this a useful check
    resp = client.get("/")
    assert resp.status_code in (200, 405)  # nosec B101


def test_lookup_missing_hash():
    """POST to /lookup with empty body returns 400."""
    client = app.test_client()
    resp = client.post("/lookup", json={})
    assert resp.status_code == 400  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "required" in data["message"].lower()  # nosec B101


def test_lookup_invalid_hash():
    """Invalid hash format returns 400."""
    client = app.test_client()
    # Too short to be any valid hash
    resp = client.post("/lookup", json={"hash_value": "abc123"})
    assert resp.status_code == 400  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "invalid" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_valid_md5(mock_config, mock_get):
    """Valid MD5 hash calls API correctly."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "classification": "malicious",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",  # pragma: allowlist secret
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # pragma: allowlist secret
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # pragma: allowlist secret
    }
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 200  # nosec B101
    data = resp.get_json()
    assert data["success"] is True  # nosec B101
    assert data["classification"] == "malicious"  # nosec B101
    assert data["md5"] == "d41d8cd98f00b204e9800998ecf8427e"  # nosec B101  # pragma: allowlist secret


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_hash_not_found(mock_config, mock_get):
    """API 404 returns proper error message."""
    mock_response = Mock()
    mock_response.status_code = 404
    mock_response.text = "Not found"
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 404  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "not found" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_hash_not_found_in_200_response(mock_config, mock_get):
    """Hash not found message in 200 response is handled correctly."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": "Hash not found.",
        "hash_value": "d41d8cd98f00b204e9800998ecf8427e",  # pragma: allowlist secret
    }
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 404  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "not found" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_timeout_error(mock_config, mock_get):
    """Timeout error returns proper error message."""
    mock_get.side_effect = requests.Timeout("Connection timed out")

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 504  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "timed out" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_connection_error(mock_config, mock_get):
    """Connection error returns proper error message."""
    mock_get.side_effect = requests.ConnectionError("Failed to connect")

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 503  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "connect" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_rate_limit_error(mock_config, mock_get):
    """429 rate limit returns user-friendly message."""
    mock_response = Mock()
    mock_response.status_code = 429
    mock_response.text = "Rate limited"
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 429  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "limit" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_invalid_json_response(mock_config, mock_get):
    """Invalid JSON response returns proper error."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 502  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_lookup_auth_error(mock_config, mock_get):
    """403 auth error returns user-friendly message."""
    mock_response = Mock()
    mock_response.status_code = 403
    mock_response.text = "Forbidden"
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 403  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "authentication" in data["message"].lower()  # nosec B101


# ============================================================================
# Upload endpoint tests
# ============================================================================


@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_missing_file(mock_config, mock_post):
    """Upload without file returns 400."""
    client = app.test_client()
    resp = client.post("/upload", data={"email": "test@example.com"})

    assert resp.status_code == 400  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101


@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_missing_email(mock_config, mock_post):
    """Upload without email returns 400."""
    client = app.test_client()
    resp = client.post(
        "/upload",
        data={"file": (BytesIO(b"test content"), "test.txt")},
        content_type="multipart/form-data",
    )

    assert resp.status_code == 400  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_success(mock_config, mock_post, mock_get):
    """Successful file upload returns classification."""
    # Mock upload response
    upload_resp = Mock()
    upload_resp.status_code = 201
    upload_resp.json.return_value = {
        "detail": {"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}  # pragma: allowlist secret
    }

    # Mock status response
    status_resp = Mock()
    status_resp.status_code = 200
    status_resp.json.return_value = {"results": [{"status": "processed"}]}

    mock_post.side_effect = [upload_resp, status_resp]

    # Mock classification response
    classification_resp = Mock()
    classification_resp.status_code = 200
    classification_resp.json.return_value = {
        "classification": "goodware",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",  # pragma: allowlist secret
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # pragma: allowlist secret
        "sha256": "e3b0c44298fc1c149afbf4c8996fb924",  # pragma: allowlist secret
    }
    mock_get.return_value = classification_resp

    client = app.test_client()
    resp = client.post(
        "/upload",
        data={
            "file": (BytesIO(b"test content"), "test.txt"),
            "email": "test@example.com",
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 200  # nosec B101
    data = resp.get_json()
    assert data["success"] is True  # nosec B101
    assert data["classification"] == "goodware"  # nosec B101


@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_api_timeout(mock_config, mock_post):
    """Upload timeout returns proper error."""
    mock_post.side_effect = requests.Timeout("Connection timed out")

    client = app.test_client()
    resp = client.post(
        "/upload",
        data={
            "file": (BytesIO(b"test content"), "test.txt"),
            "email": "test@example.com",
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 504  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "timed out" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_file_too_large(mock_config, mock_post):
    """413 file size error returns user-friendly message."""
    mock_resp = Mock()
    mock_resp.status_code = 413
    mock_resp.text = "Request Entity Too Large"
    mock_post.return_value = mock_resp

    client = app.test_client()
    resp = client.post(
        "/upload",
        data={
            "file": (BytesIO(b"test content"), "test.txt"),
            "email": "test@example.com",
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 413  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "size" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_rate_limited(mock_config, mock_post):
    """429 rate limit returns user-friendly message."""
    mock_resp = Mock()
    mock_resp.status_code = 429
    mock_resp.text = "Rate limited"
    mock_post.return_value = mock_resp

    client = app.test_client()
    resp = client.post(
        "/upload",
        data={
            "file": (BytesIO(b"test content"), "test.txt"),
            "email": "test@example.com",
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 429  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "resources" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_invalid_response_structure(mock_config, mock_post):
    """Invalid upload response structure returns error."""
    mock_resp = Mock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"unexpected": "structure"}  # Missing "detail"
    mock_post.return_value = mock_resp

    client = app.test_client()
    resp = client.post(
        "/upload",
        data={
            "file": (BytesIO(b"test content"), "test.txt"),
            "email": "test@example.com",
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 502  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101


@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_missing_sha1_in_response(mock_config, mock_post):
    """Missing sha1 in upload response returns error."""
    mock_resp = Mock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"detail": {"md5": "abc123"}}  # Missing "sha1"
    mock_post.return_value = mock_resp

    client = app.test_client()
    resp = client.post(
        "/upload",
        data={
            "file": (BytesIO(b"test content"), "test.txt"),
            "email": "test@example.com",
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 502  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "missing hash" in data["message"].lower()  # nosec B101


@patch("anon_analyze.app.time.sleep", return_value=None)  # Speed up test
@patch("anon_analyze.app.requests.post")
@patch("anon_analyze.app._get_config", return_value=_mock_config())
def test_upload_polling_consecutive_errors(mock_config, mock_post, mock_sleep):
    """Consecutive polling errors trigger fail-fast."""
    # Mock upload response
    upload_resp = Mock()
    upload_resp.status_code = 201
    upload_resp.json.return_value = {
        "detail": {"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}  # pragma: allowlist secret
    }

    # Mock status responses - all fail
    status_resp = Mock()
    status_resp.status_code = 500
    status_resp.text = "Internal Server Error"

    # First call is upload, rest are status polls
    mock_post.side_effect = [upload_resp, status_resp, status_resp, status_resp]

    client = app.test_client()
    resp = client.post(
        "/upload",
        data={
            "file": (BytesIO(b"test content"), "test.txt"),
            "email": "test@example.com",
        },
        content_type="multipart/form-data",
    )

    assert resp.status_code == 503  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "status" in data["message"].lower()  # nosec B101
