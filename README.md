## Disclaimer of Warranty

This application is provided “as is” and “as available” without any warranties of any kind, either express or implied.

Reversing Labs make no representations or warranties of any kind, including but not limited to:

- The accuracy, completeness, or timeliness of the information submitted or received via this application;
- The functionality, availability, or performance of the application;
- The security, integrity, or confidentiality of submitted files or user data; or
- The fitness of this application for any particular purpose.

Use of this application is at your own risk. By using this application, you acknowledge that any data submitted to third-party services (e.g., ReversingLabs Spectra Analyze) may be subject to their own terms and conditions.

In no event shall the developer be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising out of or in any way connected with the use or misuse of this application.

## Quickstart

```bash
# local dev
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r dev-requirements.txt
pre-commit install
pytest

# build & run container
docker build -t anon-analyze:local .
# Make sure you set the ANALYZE_API_BASE and ANALYZE_API_TOKEN env vars
docker run --rm --env-file ./.env -p 8000:8000 anon-analyze:local
```

## CI/CD Overview

- Every push/PR: Lint, test, pip-audit, Bandit (SAST).
- On push to `main` and tags `v*`: Build image, scan with Trivy, and push to GHCR.
- Nightly: re-scan latest image with Trivy.

See `.github/workflows/` for details.
