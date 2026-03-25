# RedForge Docker Image
# Runs as non-root user. No secrets baked in — pass via environment variables.

FROM python:3.11-slim AS builder

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[all-providers]"

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Security: run as non-root
RUN groupadd --gid 1001 redforge && \
    useradd --uid 1001 --gid 1001 --no-create-home --shell /bin/false redforge

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source
COPY redforge/ ./redforge/
COPY pyproject.toml .

# Install in editable-like mode
RUN pip install --no-cache-dir --no-deps -e .

# Create results directory with correct permissions
RUN mkdir -p /app/scan_results && chown redforge:redforge /app/scan_results

USER redforge

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["redforge", "serve", "--host", "0.0.0.0", "--port", "8000"]
