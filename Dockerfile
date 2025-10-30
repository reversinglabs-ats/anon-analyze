# syntax=docker/dockerfile:1

# Stage 1: Builder - Install dependencies and application
FROM python:3.11-slim AS builder

# Prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy dependency manifests first for better Docker layer caching
COPY requirements.txt /app/requirements.txt

# Install dependencies to user site-packages for easy copying
RUN pip install --upgrade pip && \
    pip install --user --no-cache-dir -r /app/requirements.txt

# Move the code over and install the application package
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
RUN pip install --user --no-cache-dir .

# Create uploads directory that will be copied to runtime stage
RUN mkdir -p /app/uploads

# Stage 2: Runtime - Distroless Python image
FROM gcr.io/distroless/python3-debian12

# Prevent Python from buffering stdout/stderr and writing .pyc files
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /root/.local /home/nonroot/.local
COPY --from=builder --chown=nonroot:nonroot /app/src /app/src
COPY --from=builder --chown=nonroot:nonroot /app/uploads /app/uploads

# Set HOME so Python can find .local packages
ENV HOME=/home/nonroot

EXPOSE 8000

USER nonroot:nonroot

# If the Flask app instance is called "app" inside app.py, WSGI module path is "app:app"
CMD ["-m", "gunicorn", "-b", "0.0.0.0:8000", "anon_analyze.app:app"]
