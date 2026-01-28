# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.4] - 2026-01-28

### Changed
- Version bump to rebuild the Docker image and remediate three medium-severity vulnerabilities

## [1.4.3] - 2026-01-23

### Changed
- Result box color now changes based on file classification (malicious, suspicious, known, unknown)
- Improved error handling when Spectra Analyze responds with unexpected data
- Environment variable validation now occurs on startup with clear error messages

### Fixed
- Linting errors resolved
- Makefile updated to simplify pre-commit hook installation

## [1.4.2] - 2026-01-23

### Changed
- Improved error handling for Spectra Analyze API responses
- Reorganized Makefile for better developer experience

## [1.4.1] - 2026-01-23

### Added
- `ANALYZE_SSL_VERIFY` environment variable to disable SSL verification for outbound API requests

### Fixed
- README documentation corrections and improvements

## [1.4.0] - 2026-01-20

### Added
- Hash lookup functionality via new `/lookup` endpoint
- Support for MD5, SHA-1, SHA-256, and SHA-512 hash lookups
- UI option to lookup files by hash instead of uploading

## [1.3.1] - 2026-01-20

### Added
- Display MD5 and SHA-256 hashes in analysis results

## [1.3.0] - 2026-01-20

### Added
- HTTPS/TLS support for incoming connections via `ENABLE_TLS` environment variable
- Auto-generated self-signed certificates when TLS is enabled without custom certs
- `TLS_CERT_PATH` and `TLS_KEY_PATH` options for custom certificates

## [1.2.0] - 2026-01-20

### Added
- Website CSS styling for improved user interface
- Progress bar during file upload and analysis

## [1.1.0] - 2025-10-29

### Added
- Docker support with distroless container image
- GitHub Actions CI/CD pipeline
- Chainguard base images for security

### Changed
- Build process optimized for containerized deployment

## [1.0.0] - 2025-10-27

### Added
- Initial release
- Web interface for anonymous file uploads
- Integration with ReversingLabs Spectra Analyze REST API
- File submission and classification retrieval
- Flask-based web server with gunicorn for production

[Unreleased]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.4.4...HEAD
[1.4.4]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.4.4...v1.4.4
[1.4.3]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/reversinglabs-ats/anon-analyze/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/reversinglabs-ats/anon-analyze/releases/tag/v1.0.0
