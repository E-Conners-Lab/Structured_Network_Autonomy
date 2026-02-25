# Multi-stage build — minimal production image
# SECURITY: non-root user, no secrets in ENV, read-only filesystem

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir --target=/install .

# --- Production image ---
FROM python:3.12-slim

# Security: non-root user
RUN groupadd -r sna && useradd -r -g sna -s /sbin/nologin sna

WORKDIR /app

COPY --from=builder /install /usr/local/lib/python3.12/site-packages/
COPY src/ ./src/
COPY policies/ ./policies/
COPY alembic.ini ./

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

USER sna

EXPOSE 8000

# Secrets mounted at runtime via Docker secrets or volume — never in ENV
CMD ["python", "-m", "uvicorn", "sna.api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--factory"]
