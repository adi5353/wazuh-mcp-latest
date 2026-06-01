#!/usr/bin/env python3
"""CI lint: every tool module must declare REQUIRED_ROLE.

Exit 0 — all modules have a REQUIRED_ROLE declaration.
Exit 1 — one or more modules are missing it (prints offenders).

Run from the repo root:
    python scripts/lint_tool_roles.py
"""
from __future__ import annotations

import os
import sys

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "wazuh_mcp", "tools")
VALID_ROLES = {"ROLE.VIEWER", "ROLE.ANALYST", "ROLE.RESPONDER", "ROLE.ADMIN"}


def check() -> list[str]:
    errors: list[str] = []
    for fname in sorted(os.listdir(TOOLS_DIR)):
        if not fname.endswith(".py") or fname.startswith("__"):
            continue
        path = os.path.join(TOOLS_DIR, fname)
        content = open(path, encoding="utf-8").read()

        if "REQUIRED_ROLE" not in content:
            errors.append(f"{fname}: missing REQUIRED_ROLE declaration")
            continue

        # Verify the declared value is a recognised ROLE tier.
        found_valid = any(role in content for role in VALID_ROLES)
        if not found_valid:
            errors.append(
                f"{fname}: REQUIRED_ROLE found but value is not one of "
                f"{', '.join(sorted(VALID_ROLES))}"
            )

    return errors


if __name__ == "__main__":
    errors = check()
    if errors:
        print("RBAC lint FAILED — fix the following tool modules:\n")
        for e in errors:
            print(f"  {e}")
        print(
            "\nEach tool module must declare a module-level REQUIRED_ROLE, e.g.:\n"
            "    from ..rbac import ROLE\n"
            "    REQUIRED_ROLE = ROLE.VIEWER   # or ANALYST / RESPONDER / ADMIN\n\n"
            "This is enforced structurally in ToolMiddleware so every tool in the\n"
            "module inherits the minimum access level at registration time."
        )
        sys.exit(1)
    print(f"RBAC lint OK — all {sum(1 for f in os.listdir(TOOLS_DIR) if f.endswith('.py') and not f.startswith('__'))} tool modules have REQUIRED_ROLE.")
    sys.exit(0)
