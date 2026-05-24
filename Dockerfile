FROM python:3.12-slim

# ── Non-root user ─────────────────────────────────────────────────────────────
# Create a dedicated system user. UID/GID 1001 avoids collision with common
# host UIDs while still being unprivileged.
RUN groupadd --gid 1001 wazuhmcp \
 && useradd --uid 1001 --gid 1001 --no-create-home --shell /sbin/nologin wazuhmcp

WORKDIR /app

# ── Dependencies (cached layer) ───────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source ────────────────────────────────────────────────────────
COPY wazuh_mcp/ ./wazuh_mcp/
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# ── Log directory owned by app user ──────────────────────────────────────────
RUN mkdir -p /app/logs && chown -R wazuhmcp:wazuhmcp /app/logs

# ── Drop to non-root ──────────────────────────────────────────────────────────
USER wazuhmcp

EXPOSE 8000

# Healthcheck via Python (no curl dependency, works in slim image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

CMD ["python", "-m", "wazuh_mcp"]
