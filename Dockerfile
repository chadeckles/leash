FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="Leash" \
      org.opencontainers.image.description="AI Agent Identity, Authorization, and Audit Layer" \
      org.opencontainers.image.source="https://github.com/chadeckles/leash" \
      org.opencontainers.image.license="Apache-2.0"

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    LEASH_HOME=/data

WORKDIR /src

# Dependencies first (layer cache), then the project itself
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --extra server --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --extra server --no-editable

# Non-root runtime user; all state (db, keys, policies) lives in /data
RUN groupadd -r leash && useradd -r -g leash -d /data -s /sbin/nologin leash \
    && mkdir -p /data && chown -R leash:leash /data

USER leash
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"]

CMD ["leash", "start", "--host", "0.0.0.0", "--port", "8000"]
