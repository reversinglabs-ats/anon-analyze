## Disclaimer of Warranty

This application is provided "as is" and "as available" without any warranties of any kind, either express or implied.

Reversing Labs make no representations or warranties of any kind, including but not limited to:

- The accuracy, completeness, or timeliness of the information submitted or received via this application;
- The functionality, availability, or performance of the application;
- The security, integrity, or confidentiality of submitted files or user data; or
- The fitness of this application for any particular purpose.

Use of this application is at your own risk. By using this application, you acknowledge that any data submitted to third-party services (e.g., ReversingLabs Spectra Analyze) may be subject to their own terms and conditions.

In no event shall the developer be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising out of or in any way connected with the use or misuse of this application.

## Usage

### Configuration

Create a `.env` file with your Spectra Analyze credentials:

```
ANALYZE_API_BASE=https://your.appliance.reversinglabs.com
ANALYZE_API_TOKEN=your40characterhexadecimalapitokenhere
```

#### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `ANALYZE_API_BASE` | Base URL of your Spectra Analyze instance (no trailing slash) |
| `ANALYZE_API_TOKEN` | API authentication token for Spectra Analyze (40 hex characters) |

#### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANALYZE_SSL_VERIFY` | `true` | Set to `false` to disable SSL verification for outbound API requests (use only in trusted networks) |
| `ENABLE_TLS` | `false` | Set to `true` to enable HTTPS mode for incoming connections |
| `TLS_CERT_PATH` | (none) | Path to TLS certificate file (from container's perspective) |
| `TLS_KEY_PATH` | (none) | Path to TLS private key file (from container's perspective) |

### Quick Start

Pull and run the pre-built container image:

```bash
docker pull ghcr.io/reversinglabs-ats/anon-analyze:latest

docker run --rm --env-file ./.env -p 8000:8000 ghcr.io/reversinglabs-ats/anon-analyze:latest
```

### TLS/HTTPS Mode

The application supports optional HTTPS mode for encrypted connections. Both HTTP and HTTPS modes use port 8000 inside the container.

#### Auto-Generated Self-Signed Certificate

When `ENABLE_TLS=true` is set without providing certificate paths, the application automatically generates a self-signed certificate:

```bash
docker run --rm --env-file ./.env -e ENABLE_TLS=true -p 8000:8000 ghcr.io/reversinglabs-ats/anon-analyze:latest
curl -k https://localhost:8000/
```

The `-k` flag tells curl to accept the self-signed certificate.

#### Using Custom Certificates

To use your own certificates, mount them into the container and set the path environment variables:

```bash
docker run --rm --env-file ./.env \
  -e ENABLE_TLS=true \
  -e TLS_CERT_PATH=/certs/cert.pem \
  -e TLS_KEY_PATH=/certs/key.pem \
  -v /path/to/your/certs:/certs:ro \
  -p 8000:8000 ghcr.io/reversinglabs-ats/anon-analyze:latest
```

Note that `TLS_CERT_PATH` and `TLS_KEY_PATH` are paths **from the container's perspective**, not the host. Both must be provided together, or neither (for auto-generated certificates).

## Development

### Local Development Setup

```bash
cp .env.example .env
# Edit .env with your Spectra Analyze instance URL and API token

python -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements.txt -r dev-requirements.txt
pre-commit install
pytest
```

### Build and Run Container Locally

```bash
# Build the image
docker build -t anon-analyze:local .

# Run in HTTP mode (default)
docker run --rm --env-file ./.env -p 8000:8000 anon-analyze:local

# Run in HTTPS mode with auto-generated self-signed certificate
docker run --rm --env-file ./.env -e ENABLE_TLS=true -p 8000:8000 anon-analyze:local
```

## CI/CD Overview

- Every push/PR: Lint, test, pip-audit, Bandit (SAST).
- On push to `main` and tags `v*`: Build image, scan with Trivy, and push to GHCR.
- Nightly: re-scan latest image with Trivy.

See `.github/workflows/` for details.
