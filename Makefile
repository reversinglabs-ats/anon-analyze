PYTHON := python3

.PHONY: install lint test run docker-build docker-run docker-run-tls

install:
	pip install -r requirements.txt
	pip install -r dev-requirements.txt

lint:
	ruff check .
	ruff format --check .

test:
	pytest

run:
	FLASK_ENV=development FLASK_APP=anon_analyze.app flask run --host=0.0.0.0 --port=8000

docker-build:
	docker build -t anon-analyze:local .

docker-run:
	docker run --rm --env-file ./.env -p 8000:8000 anon-analyze:local

docker-run-tls:
	docker run --rm --env-file ./.env -e ENABLE_TLS=true -p 8000:8000 anon-analyze:local
