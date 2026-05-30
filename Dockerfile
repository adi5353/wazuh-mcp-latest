FROM python:3.12-slim

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN groupadd --gid 1001 wazuhmcp \
 && useradd --uid 1001 --gid 1001 --no-create-home --shell /sbin/nologin wazuhmcp

WORKDIR /app

# ── Dependencies (cached layer — only reinstall when pyproject.toml changes) ──
COPY pyproject.toml requirements.lock ./
# Stub wazuh_mcp package so pip can resolve the dynamic version attr at install time
COPY wazuh_mcp/__init__.py ./wazuh_mcp/__init__.py
RUN pip install --no-cache-dir -r requirements.lock && pip install --no-cache-dir --no-deps -e .

# ── Application source (separate layer — changes here don't bust dep cache) ───
COPY wazuh_mcp/ ./wazuh_mcp/

# ── Writable runtime directories owned by app user ────────────────────────────
RUN mkdir -p /app/logs /app/workspaces \
 && chown -R wazuhmcp:wazuhmcp /app/logs /app/workspaces

# ── Drop to non-root ──────────────────────────────────────────────────────────
USER wazuhmcp

EXPOSE 8000

# Healthcheck via pure Python — no curl dependency, works in slim image
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

CMD ["python", "-m", "wazuh_mcp"]
