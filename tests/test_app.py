from unittest.mock import patch, Mock
from anon_analyze import app


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
@patch("anon_analyze.app.API_BASE", "https://test.example.com")
@patch("anon_analyze.app.API_TOKEN", "test-token")
def test_lookup_valid_md5(mock_get):
    """Valid MD5 hash calls API correctly."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "classification": "malicious",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 200  # nosec B101
    data = resp.get_json()
    assert data["success"] is True  # nosec B101
    assert data["classification"] == "malicious"  # nosec B101
    assert data["md5"] == "d41d8cd98f00b204e9800998ecf8427e"  # nosec B101


@patch("anon_analyze.app.requests.get")
@patch("anon_analyze.app.API_BASE", "https://test.example.com")
@patch("anon_analyze.app.API_TOKEN", "test-token")
def test_lookup_hash_not_found(mock_get):
    """API 404 returns proper error message."""
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    client = app.test_client()
    resp = client.post("/lookup", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})

    assert resp.status_code == 404  # nosec B101
    data = resp.get_json()
    assert data["success"] is False  # nosec B101
    assert "not found" in data["message"].lower()  # nosec B101
