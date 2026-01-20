"""Entrypoint script for the anon-analyze application.

This module handles TLS configuration and launches gunicorn with the appropriate
settings based on environment variables.
"""

import os
import sys


def main() -> None:
    """Main entrypoint for the application."""
    enable_tls = os.getenv("ENABLE_TLS", "false").lower() == "true"
    cert_path = os.getenv("TLS_CERT_PATH")
    key_path = os.getenv("TLS_KEY_PATH")

    bind = "0.0.0.0:8000"
    # Use Python interpreter with -m to run gunicorn as a module
    # This works in distroless images where gunicorn isn't directly in PATH
    cmd = [sys.executable, "-m", "gunicorn", "-b", bind, "anon_analyze.app:app"]

    if enable_tls:
        if cert_path and key_path:
            # Validate that both files exist
            if not os.path.isfile(cert_path):
                sys.exit(f"Error: Certificate file not found: {cert_path}")
            if not os.path.isfile(key_path):
                sys.exit(f"Error: Key file not found: {key_path}")
            cmd.extend(["--certfile", cert_path, "--keyfile", key_path])
        elif not cert_path and not key_path:
            # Generate self-signed certificate
            from anon_analyze.tls_utils import generate_self_signed_cert

            cert, key = generate_self_signed_cert()
            print(f"Generated self-signed certificate: {cert}")
            cmd.extend(["--certfile", cert, "--keyfile", key])
        else:
            sys.exit("Error: Both TLS_CERT_PATH and TLS_KEY_PATH must be set, or neither")

    os.execvp(sys.executable, cmd)


if __name__ == "__main__":
    main()
