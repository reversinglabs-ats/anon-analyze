PYTHON := python3

.PHONY: install setup lint lint-fix test run docker-build docker-run docker-run-tls \
       changelog-check changelog-entry release-notes gh-release

install:
	uv venv --quiet
	uv pip install -r requirements.txt
	uv pip install -r dev-requirements.txt

setup: install
	uv run pre-commit install
	@echo "Pre-commit hooks installed!"

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

test:
	uv run pytest

run:
	FLASK_ENV=development FLASK_APP=anon_analyze.app uv run flask run --host=0.0.0.0 --port=8000

docker-build:
	docker build -t anon-analyze:local .

docker-run:
	docker run --rm --env-file ./.env -p 8000:8000 anon-analyze:local

docker-run-tls:
	docker run --rm --env-file ./.env -e ENABLE_TLS=true -p 8000:8000 anon-analyze:local

# Changelog and release targets
changelog-check:
	@echo "Checking CHANGELOG.md format..."
	@grep -q "## \[Unreleased\]" CHANGELOG.md || (echo "Missing [Unreleased] section" && exit 1)
	@grep -q "keepachangelog.com" CHANGELOG.md || (echo "Missing Keep a Changelog reference" && exit 1)
	@echo "CHANGELOG.md format OK"

changelog-entry:
	@echo "=== Recent commits (to help write changelog) ==="
	@git log --oneline -15
	@echo ""
	@echo "=== Unreleased section ==="
	@sed -n '/## \[Unreleased\]/,/## \[/p' CHANGELOG.md | head -20

release-notes:
	@VERSION=$$(grep -m1 '^version' pyproject.toml | cut -d'"' -f2); \
	echo "Release notes for v$$VERSION:"; \
	echo ""; \
	sed -n "/^## \[$$VERSION\]/,/^## \[/p" CHANGELOG.md | sed '1d;$$d'

gh-release:
	@VERSION=$$(grep -m1 '^version' pyproject.toml | cut -d'"' -f2); \
	NOTES=$$(sed -n "/^## \[$$VERSION\]/,/^## \[/p" CHANGELOG.md | sed '1d;$$d'); \
	gh release create "v$$VERSION" --title "v$$VERSION" --notes "$$NOTES"
