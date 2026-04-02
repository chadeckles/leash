FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="Leash" \
      org.opencontainers.image.description="AI Agent Identity, Authorization, and Audit Layer" \
      org.opencontainers.image.source="https://github.com/chadeckles/leash" \
      org.opencontainers.image.license="Apache-2.0"

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for runtime
RUN groupadd -r leash && useradd -r -g leash -d /app -s /sbin/nologin leash \
    && mkdir -p /app/data /app/.keys \
    && chown -R leash:leash /app/data /app/.keys

USER leash

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
