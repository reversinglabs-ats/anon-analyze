"""Tests for configuration validation."""

import pytest
from anon_analyze.config import (
    ConfigurationError,
    validate_api_token,
    validate_api_base,
    validate_ssl_verify,
    load_config,
    AppConfig,
)


class TestValidateApiToken:
    """Tests for validate_api_token function."""

    def test_valid_token_lowercase(self):
        """Valid 40-char lowercase hex token."""
        token = "a" * 40
        assert validate_api_token(token) == token  # nosec B101

    def test_valid_token_uppercase(self):
        """Valid 40-char uppercase hex token."""
        token = "A" * 40
        assert validate_api_token(token) == token  # nosec B101

    def test_valid_token_mixed_case(self):
        """Valid 40-char mixed case hex token."""
        token = "aAbBcCdDeEfF0123456789" + "a" * 18
        assert validate_api_token(token) == token  # nosec B101

    def test_valid_token_with_whitespace(self):
        """Whitespace is stripped from token."""
        token = "a" * 40
        assert validate_api_token(f"  {token}  ") == token  # nosec B101

    def test_missing_token_none(self):
        """None token raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_token(None)
        assert "required but not set" in str(exc_info.value)  # nosec B101

    def test_missing_token_empty(self):
        """Empty string token raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_token("")
        assert "required but not set" in str(exc_info.value)  # nosec B101

    def test_missing_token_whitespace_only(self):
        """Whitespace-only token raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_token("   ")
        assert "required but not set" in str(exc_info.value)  # nosec B101

    def test_token_too_short(self):
        """Token with wrong length raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_token("a" * 38)
        assert "exactly 40 hex characters" in str(exc_info.value)  # nosec B101
        assert "got 38" in str(exc_info.value)  # nosec B101

    def test_token_too_long(self):
        """Token with wrong length raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_token("a" * 42)
        assert "exactly 40 hex characters" in str(exc_info.value)  # nosec B101
        assert "got 42" in str(exc_info.value)  # nosec B101

    def test_token_non_hex_chars(self):
        """Token with non-hex characters raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_token("g" * 40)  # 'g' is not hex
        assert "hexadecimal characters" in str(exc_info.value)  # nosec B101


class TestValidateApiBase:
    """Tests for validate_api_base function."""

    def test_valid_https_url(self):
        """Valid HTTPS URL passes validation."""
        url = "https://example.reversinglabs.com"
        assert validate_api_base(url) == url  # nosec B101

    def test_valid_http_url(self):
        """Valid HTTP URL passes validation."""
        url = "http://example.reversinglabs.com"
        assert validate_api_base(url) == url  # nosec B101

    def test_trailing_slash_stripped(self):
        """Trailing slash is removed."""
        result = validate_api_base("https://example.com/")
        assert result == "https://example.com"  # nosec B101

    def test_multiple_trailing_slashes_stripped(self):
        """Multiple trailing slashes are removed."""
        result = validate_api_base("https://example.com///")
        assert result == "https://example.com"  # nosec B101

    def test_whitespace_stripped(self):
        """Whitespace is stripped from URL."""
        result = validate_api_base("  https://example.com  ")
        assert result == "https://example.com"  # nosec B101

    def test_url_with_path_preserved(self):
        """URL with path is preserved (minus trailing slash)."""
        result = validate_api_base("https://example.com/api/v1/")
        assert result == "https://example.com/api/v1"  # nosec B101

    def test_missing_url_none(self):
        """None URL raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_base(None)
        assert "required but not set" in str(exc_info.value)  # nosec B101

    def test_missing_url_empty(self):
        """Empty URL raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_base("")
        assert "required but not set" in str(exc_info.value)  # nosec B101

    def test_url_with_double_quotes(self):
        """URL with surrounding double quotes raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_base('"https://example.com"')
        assert "surrounding quotes" in str(exc_info.value)  # nosec B101

    def test_url_with_single_quotes(self):
        """URL with surrounding single quotes raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_base("'https://example.com'")
        assert "surrounding quotes" in str(exc_info.value)  # nosec B101

    def test_url_missing_scheme(self):
        """URL without scheme raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_base("example.com")
        assert "http://" in str(exc_info.value)  # nosec B101
        assert "https://" in str(exc_info.value)  # nosec B101

    def test_url_invalid_scheme(self):
        """URL with invalid scheme raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_base("ftp://example.com")
        assert "http://" in str(exc_info.value)  # nosec B101

    def test_url_scheme_only(self):
        """URL with scheme but no hostname raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_api_base("https://")
        assert "valid" in str(exc_info.value).lower()  # nosec B101


class TestValidateSslVerify:
    """Tests for validate_ssl_verify function."""

    def test_default_none_returns_true(self):
        """None value returns True (default)."""
        assert validate_ssl_verify(None) is True  # nosec B101

    def test_true_string(self):
        """'true' returns True."""
        assert validate_ssl_verify("true") is True  # nosec B101

    def test_false_string(self):
        """'false' returns False."""
        assert validate_ssl_verify("false") is False  # nosec B101

    def test_case_insensitive_true(self):
        """Case-insensitive 'TRUE' returns True."""
        assert validate_ssl_verify("TRUE") is True  # nosec B101
        assert validate_ssl_verify("True") is True  # nosec B101

    def test_case_insensitive_false(self):
        """Case-insensitive 'FALSE' returns False."""
        assert validate_ssl_verify("FALSE") is False  # nosec B101
        assert validate_ssl_verify("False") is False  # nosec B101

    def test_numeric_true(self):
        """'1' and 'yes' return True."""
        assert validate_ssl_verify("1") is True  # nosec B101
        assert validate_ssl_verify("yes") is True  # nosec B101

    def test_numeric_false(self):
        """'0' and 'no' return False."""
        assert validate_ssl_verify("0") is False  # nosec B101
        assert validate_ssl_verify("no") is False  # nosec B101

    def test_whitespace_stripped(self):
        """Whitespace is stripped."""
        assert validate_ssl_verify("  true  ") is True  # nosec B101
        assert validate_ssl_verify("  false  ") is False  # nosec B101

    def test_invalid_value(self):
        """Invalid value raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            validate_ssl_verify("maybe")
        assert "'true' or 'false'" in str(exc_info.value)  # nosec B101
        assert "maybe" in str(exc_info.value)  # nosec B101


class TestAppConfig:
    """Tests for AppConfig dataclass."""

    def test_url_properties(self):
        """URL properties are constructed correctly."""
        config = AppConfig(
            api_token="a" * 40,
            api_base="https://example.com",
            ssl_verify=True,
        )
        assert config.submit_url == "https://example.com/api/submit/file/"  # nosec B101
        assert config.status_url == "https://example.com/api/samples/status/"  # nosec B101
        assert config.classification_url == "https://example.com/api/samples/v3/"  # nosec B101


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_valid_config(self, monkeypatch):
        """Valid environment variables load successfully."""
        monkeypatch.setenv("ANALYZE_API_TOKEN", "a" * 40)
        monkeypatch.setenv("ANALYZE_API_BASE", "https://example.com")
        monkeypatch.setenv("ANALYZE_SSL_VERIFY", "false")

        config = load_config()

        assert config.api_token == "a" * 40  # nosec B101
        assert config.api_base == "https://example.com"  # nosec B101
        assert config.ssl_verify is False  # nosec B101

    def test_load_config_defaults_ssl_verify(self, monkeypatch):
        """SSL verify defaults to True when not set."""
        monkeypatch.setenv("ANALYZE_API_TOKEN", "a" * 40)
        monkeypatch.setenv("ANALYZE_API_BASE", "https://example.com")
        monkeypatch.delenv("ANALYZE_SSL_VERIFY", raising=False)

        config = load_config()

        assert config.ssl_verify is True  # nosec B101

    def test_load_config_missing_token(self, monkeypatch):
        """Missing token raises ConfigurationError."""
        monkeypatch.delenv("ANALYZE_API_TOKEN", raising=False)
        monkeypatch.setenv("ANALYZE_API_BASE", "https://example.com")

        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        assert "ANALYZE_API_TOKEN" in str(exc_info.value)  # nosec B101

    def test_load_config_missing_base(self, monkeypatch):
        """Missing base URL raises ConfigurationError."""
        monkeypatch.setenv("ANALYZE_API_TOKEN", "a" * 40)
        monkeypatch.delenv("ANALYZE_API_BASE", raising=False)

        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        assert "ANALYZE_API_BASE" in str(exc_info.value)  # nosec B101

    def test_load_config_invalid_token(self, monkeypatch):
        """Invalid token raises ConfigurationError."""
        monkeypatch.setenv("ANALYZE_API_TOKEN", "invalid")
        monkeypatch.setenv("ANALYZE_API_BASE", "https://example.com")

        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        assert "ANALYZE_API_TOKEN" in str(exc_info.value)  # nosec B101

    def test_load_config_quoted_base(self, monkeypatch):
        """Quoted base URL raises ConfigurationError with helpful message."""
        monkeypatch.setenv("ANALYZE_API_TOKEN", "a" * 40)
        monkeypatch.setenv("ANALYZE_API_BASE", '"https://example.com"')

        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        assert "quotes" in str(exc_info.value)  # nosec B101
