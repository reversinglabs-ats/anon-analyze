# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     PIP_NO_CACHE_DIR=1

# curl for healthcheck/debug; build-essential only if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m appuser
WORKDIR /app

# Copy dependency manifests first for better Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# Move the code over and install it
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
RUN pip install .

EXPOSE 8000

# If the Flask app instance is called "app" inside app.py, WSGI module path is "app:app"
CMD ["gunicorn", "-b", "0.0.0.0:8000", "anon_analyze.app:app"]
