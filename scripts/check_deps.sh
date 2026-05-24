#!/usr/bin/env bash
# Scan Python dependencies for known vulnerabilities.
# Run before releasing or in CI.
set -euo pipefail

echo "=== pip-audit: scanning for vulnerable packages ==="
pip-audit -r requirements.txt --format=markdown || {
    echo "pip-audit found vulnerabilities — review above and update requirements.txt"
    exit 1
}

echo ""
echo "=== Checking for unpinned requirements ==="
while IFS= read -r line; do
    # Skip comments and blank lines
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    # Warn if no exact version pin (==)
    if [[ "$line" != *"=="* ]]; then
        echo "WARNING: '$line' is not pinned to an exact version (use ==)"
    fi
done < requirements.txt

echo ""
echo "All dependency checks complete."
