#!/usr/bin/env python3
"""Regenerate the MCP tool inventory so README counts can't drift (Issue 12).

Parses ``wazuh_mcp/`` with the ``ast`` module, finds functions decorated with
``@mcp.tool()`` / ``@mcp.prompt()``, and emits a per-module Markdown table plus
headline counts.

NB: this uses an AST walk, not a regex. A line-regex over the source text wrongly
counts ``@mcp.tool()`` occurrences that appear inside *docstrings* (e.g. usage
examples in rbac.py), which previously inflated the headline by 2.

Usage:
    python scripts/generate_tool_table.py            # write docs/TOOL_TABLE.md + print counts
    python scripts/generate_tool_table.py --check     # exit 1 if README counts are stale
"""
from __future__ import annotations

import argparse
import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "wazuh_mcp"
README = ROOT / "README.md"
INIT = PKG / "__init__.py"
OUT = ROOT / "docs" / "TOOL_TABLE.md"

# Headline in README, e.g. "**240 tools** across 55 domain modules"
_HEADLINE = re.compile(r"\*\*(\d+) tools\*\* across (\d+) domain modules")
# Shields.io badge in README, e.g. ".../badge/tools-240-brightgreen"
_BADGE = re.compile(r"(badge/tools-)(\d+)(-brightgreen)")
# Tool Reference intro prose, e.g. "(**240 tools across 55 modules**)"
_PROSE = re.compile(r"\*\*(\d+) tools across (\d+) modules\*\*")
# First version heading in README, e.g. "### v2.4 — ..."
_README_VERSION = re.compile(r"^###\s*v(\d+)\.(\d+)", re.MULTILINE)
_INIT_VERSION = re.compile(r'__version__\s*=\s*["\'](\d+)\.(\d+)')


# Local decorators that register a function as an MCP *tool* exactly like
# ``@mcp.tool()`` but conditionally (e.g. backward-compatible aliases gated by
# WAZUH_MCP_LEGACY_ALIASES). They register by default, so they count toward the
# advertised surface and the AST walk must recognise them.
_ALIAS_TOOL_DECORATORS = {"_summary_tool", "_alias_tool"}


def _decorated_names(tree: ast.Module, attr: str) -> list[str]:
    """Return names of functions carrying an ``@mcp.<attr>(...)`` decorator.

    For ``attr == "tool"`` this also counts the local alias decorators in
    ``_ALIAS_TOOL_DECORATORS`` (they wrap ``mcp.tool`` and register by default).
    """
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if (
                isinstance(target, ast.Attribute)
                and target.attr == attr
                and isinstance(target.value, ast.Name)
                and target.value.id == "mcp"
            ):
                names.append(node.name)
                break
            if (
                attr == "tool"
                and isinstance(target, ast.Name)
                and target.id in _ALIAS_TOOL_DECORATORS
            ):
                names.append(node.name)
                break
    return names


def collect() -> dict:
    by_module: dict[str, list[str]] = {}
    prompts: list[str] = []
    for path in sorted(PKG.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        tools = _decorated_names(tree, "tool")
        if tools:
            label = f"tools/{path.stem}" if path.parent.name == "tools" else path.stem
            by_module.setdefault(label, []).extend(tools)
        prompts.extend(_decorated_names(tree, "prompt"))
    total_tools = sum(len(v) for v in by_module.values())
    tool_modules = sum(1 for k in by_module if k.startswith("tools/"))
    return {
        "by_module": by_module,
        "prompts": sorted(set(prompts)),
        "total_tools": total_tools,
        "tool_modules": tool_modules,
    }


def render_markdown(data: dict) -> str:
    out = [
        "# Tool Inventory (auto-generated)",
        "",
        f"**{data['total_tools']} tools** across **{data['tool_modules']} domain modules** "
        f"in `wazuh_mcp/tools/`, plus **{len(data['prompts'])} MCP prompts**.",
        "",
        "> Regenerate with `python scripts/generate_tool_table.py`. Do not edit by hand.",
        "",
    ]
    for module in sorted(data["by_module"]):
        names = sorted(data["by_module"][module])
        out.append(f"### `{module}` ({len(names)})")
        out.append("")
        out.extend(f"- `{n}`" for n in names)
        out.append("")
    return "\n".join(out)


def _count_targets(data: dict) -> list[tuple[str, "re.Pattern[str]", str]]:
    """README locations that must reflect the live tool/module counts.

    Each entry is ``(label, pattern, expected_replacement)``. ``pattern`` must
    capture the full span to rewrite; ``expected_replacement`` is the canonical
    text those counts should produce. Keeping all three count sites in one list
    means write-mode and ``--check`` stay in lockstep — the badge and the Tool
    Reference prose previously drifted because only the headline was validated.
    """
    t, m = data["total_tools"], data["tool_modules"]
    return [
        ("headline", _HEADLINE, f"**{t} tools** across {m} domain modules"),
        ("tools badge", _BADGE, f"badge/tools-{t}-brightgreen"),
        ("Tool Reference prose", _PROSE, f"**{t} tools across {m} modules**"),
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if README headline count is stale")
    args = ap.parse_args()

    data = collect()
    summary = (f"{data['total_tools']} tools across {data['tool_modules']} domain "
               f"modules, {len(data['prompts'])} prompts")

    if args.check:
        readme = README.read_text(encoding="utf-8")
        errors: list[str] = []

        # 1. Every count site (headline, badge, prose) must match the live
        #    counts. Exact-span matching is used because substring matching is
        #    too weak — a stale "239" can coincidentally appear elsewhere.
        for label, pattern, expected in _count_targets(data):
            found = pattern.search(readme)
            if not found:
                errors.append(f"README {label} count not found.")
            elif found.group(0) != expected:
                errors.append(
                    f"README {label} is stale: says {found.group(0)!r}, expected "
                    f"{expected!r} ({data['total_tools']} tools / "
                    f"{data['tool_modules']} modules). Run generate_tool_table.py."
                )

        # 2. README's latest version heading must match __version__ (major.minor).
        iv = _INIT_VERSION.search(INIT.read_text(encoding="utf-8"))
        rv = _README_VERSION.search(readme)
        if iv and rv and (iv.group(1), iv.group(2)) != (rv.group(1), rv.group(2)):
            errors.append(
                f"Version mismatch: __version__ is {iv.group(1)}.{iv.group(2)}.x "
                f"but README's latest section is v{rv.group(1)}.{rv.group(2)}."
            )

        if errors:
            for e in errors:
                print(f"STALE: {e}", file=sys.stderr)
            return 1
        print(f"OK: README counts ({data['total_tools']} tools / "
              f"{data['tool_modules']} modules) and version are consistent.")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render_markdown(data), encoding="utf-8")

    # Rewrite all count sites in the README so the badge and Tool Reference
    # prose can never drift from the headline again.
    readme = README.read_text(encoding="utf-8")
    for _label, pattern, expected in _count_targets(data):
        readme = pattern.sub(lambda _m, e=expected: e, readme, count=1)
    README.write_text(readme, encoding="utf-8")

    print(summary)
    print(f"wrote {OUT.relative_to(ROOT)} and synced README counts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
