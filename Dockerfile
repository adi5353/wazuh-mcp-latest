# ── Stage 1: builder — install dependencies into an isolated venv ─────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Build into a self-contained venv we can copy wholesale into the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Dependencies first (cached layer — only reinstalls when the lockfile changes).
COPY pyproject.toml requirements.lock ./
# Stub wazuh_mcp package so pip can resolve the dynamic version attr at install time.
COPY wazuh_mcp/__init__.py ./wazuh_mcp/__init__.py
RUN pip install --no-cache-dir -r requirements.lock \
 && pip install --no-cache-dir --no-deps -e .

# Application source + pre-compiled bytecode (no toolchain leaks into runtime).
COPY wazuh_mcp/ ./wazuh_mcp/
RUN python -m compileall -q wazuh_mcp

# ── Stage 2: runtime — only the venv + source, dropped to a non-root user ─────
FROM python:3.12-slim AS runtime

# Non-root user
RUN groupadd --gid 1001 wazuhmcp \
 && useradd --uid 1001 --gid 1001 --no-create-home --shell /sbin/nologin wazuhmcp

WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy the resolved venv and the editable-install metadata from the builder.
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/wazuh_mcp /app/wazuh_mcp
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Writable runtime directories owned by the app user.
RUN mkdir -p /app/logs /app/workspaces \
 && chown -R wazuhmcp:wazuhmcp /app/logs /app/workspaces

USER wazuhmcp

EXPOSE 8000

# Healthcheck via pure Python — no curl dependency, works in the slim image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

CMD ["python", "-m", "wazuh_mcp"]
