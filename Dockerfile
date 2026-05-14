# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS base

# Install only what's needed
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install deps first for better layer caching
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY wazuh_mcp/ ./wazuh_mcp/

# Install the package itself (registers the wazuh-mcp entrypoint)
RUN pip install --no-cache-dir -e .

# Run as non-root
RUN useradd --create-home --uid 10001 wazuhmcp \
 && chown -R wazuhmcp:wazuhmcp /app
USER wazuhmcp

# Default to STDIO transport. Override CMD if you wire HTTP transport later.
CMD ["python", "-m", "wazuh_mcp"]
