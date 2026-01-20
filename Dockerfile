# syntax=docker/dockerfile:1

FROM cgr.dev/chainguard/python:latest-dev AS builder

USER root

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

ENV HOME=/root

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install --upgrade pip && \
    pip install --user --no-cache-dir -r /app/requirements.txt

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
RUN pip install --user --no-cache-dir .

RUN mkdir -p /app/uploads

FROM cgr.dev/chainguard/python:latest

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Builder ran as root, so we copy from /root/.local and change ownership to nonroot
COPY --from=builder --chown=nonroot:nonroot /root/.local /home/nonroot/.local
COPY --from=builder --chown=nonroot:nonroot /app/src /app/src
COPY --from=builder --chown=nonroot:nonroot /app/uploads /app/uploads

# Set HOME so Python can find .local packages
ENV HOME=/home/nonroot

EXPOSE 8000

USER nonroot:nonroot

CMD ["-m", "anon_analyze.entrypoint"]
