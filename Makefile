PYTHON := python3

.PHONY: install setup lint lint-fix test run docker-build docker-run docker-run-tls

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
