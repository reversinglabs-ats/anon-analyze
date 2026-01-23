"""Configuration loading and validation for anon-analyze."""

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse


class ConfigurationError(Exception):
    """Raised when environment configuration is invalid."""

    pass


def validate_api_token(value: str | None) -> str:
    """Validate ANALYZE_API_TOKEN format.

    Args:
        value: The token value from environment

    Returns:
        The validated and stripped token

    Raises:
        ConfigurationError: If token is missing or invalid format
    """
    if not value:
        raise ConfigurationError("ANALYZE_API_TOKEN is required but not set")

    value = value.strip()

    if not value:
        raise ConfigurationError("ANALYZE_API_TOKEN is required but not set")

    # Must be exactly 40 hexadecimal characters
    if not re.match(r"^[a-fA-F0-9]{40}$", value):
        if len(value) != 40:
            raise ConfigurationError(
                f"ANALYZE_API_TOKEN must be exactly 40 hex characters (got {len(value)})"
            )
        raise ConfigurationError(
            "ANALYZE_API_TOKEN must contain only hexadecimal characters (0-9, a-f)"
        )

    return value


def validate_api_base(value: str | None) -> str:
    """Validate ANALYZE_API_BASE format.

    Args:
        value: The base URL value from environment

    Returns:
        The validated URL with trailing slash removed

    Raises:
        ConfigurationError: If URL is missing or invalid format
    """
    if not value:
        raise ConfigurationError("ANALYZE_API_BASE is required but not set")

    value = value.strip()

    if not value:
        raise ConfigurationError("ANALYZE_API_BASE is required but not set")

    # Check for surrounding quotes (common misconfiguration)
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        raise ConfigurationError("ANALYZE_API_BASE contains surrounding quotes - remove them")

    # Check for scheme
    if not value.startswith(("http://", "https://")):
        raise ConfigurationError("ANALYZE_API_BASE must start with http:// or https://")

    # Validate URL structure
    try:
        parsed = urlparse(value)
        if not parsed.netloc:
            raise ConfigurationError("ANALYZE_API_BASE must have a valid hostname")
    except Exception:
        raise ConfigurationError("ANALYZE_API_BASE is not a valid URL")

    # Strip trailing slash for consistent URL construction
    return value.rstrip("/")


def validate_ssl_verify(value: str | None) -> bool:
    """Validate ANALYZE_SSL_VERIFY boolean string.

    Args:
        value: The SSL verify value from environment (or None for default)

    Returns:
        Boolean indicating whether SSL verification is enabled

    Raises:
        ConfigurationError: If value is not a valid boolean string
    """
    if value is None:
        return True

    value = value.strip().lower()

    if value in ("true", "1", "yes"):
        return True
    if value in ("false", "0", "no"):
        return False

    raise ConfigurationError(f"ANALYZE_SSL_VERIFY must be 'true' or 'false' (got '{value}')")


@dataclass
class AppConfig:
    """Application configuration loaded from environment variables."""

    api_token: str
    api_base: str
    ssl_verify: bool

    @property
    def submit_url(self) -> str:
        """URL for file submission endpoint."""
        return f"{self.api_base}/api/submit/file/"

    @property
    def status_url(self) -> str:
        """URL for sample status endpoint."""
        return f"{self.api_base}/api/samples/status/"

    @property
    def classification_url(self) -> str:
        """URL for sample classification endpoint (v3)."""
        return f"{self.api_base}/api/samples/v3/"


def load_config() -> AppConfig:
    """Load and validate all configuration from environment variables.

    Returns:
        AppConfig object with validated configuration

    Raises:
        ConfigurationError: If any required config is missing or invalid
    """
    api_token = validate_api_token(os.getenv("ANALYZE_API_TOKEN"))
    api_base = validate_api_base(os.getenv("ANALYZE_API_BASE"))
    ssl_verify = validate_ssl_verify(os.getenv("ANALYZE_SSL_VERIFY"))

    return AppConfig(
        api_token=api_token,
        api_base=api_base,
        ssl_verify=ssl_verify,
    )
