#!/usr/bin/env bash
# Generate a CycloneDX Software Bill of Materials (SBOM).
# Requires: pip install cyclonedx-bom
set -euo pipefail

OUTPUT_DIR="${1:-sbom}"
mkdir -p "$OUTPUT_DIR"

echo "=== Generating CycloneDX SBOM ==="
cyclonedx-py environment \
    --outfile "$OUTPUT_DIR/wazuh-mcp-sbom.json" \
    --format json \
    --schema-version 1.5

echo "SBOM written to $OUTPUT_DIR/wazuh-mcp-sbom.json"

# Also generate human-readable XML
cyclonedx-py environment \
    --outfile "$OUTPUT_DIR/wazuh-mcp-sbom.xml" \
    --format xml \
    --schema-version 1.5

echo "SBOM written to $OUTPUT_DIR/wazuh-mcp-sbom.xml"
