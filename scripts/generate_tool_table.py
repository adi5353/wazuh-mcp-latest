#!/usr/bin/env python3
"""Regenerate the MCP tool inventory so README counts can't drift (Issue 12).

Scans ``wazuh_mcp/`` for ``@mcp.tool()`` / ``@mcp.prompt()`` decorators, derives
the tool/prompt name from the following ``def``/``async def`` line, and emits a
per-module Markdown table plus headline counts.

Usage:
    python scripts/generate_tool_table.py            # write docs/TOOL_TABLE.md + print counts
    python scripts/generate_tool_table.py --check     # exit 1 if README counts are stale
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "wazuh_mcp"
README = ROOT / "README.md"
OUT = ROOT / "docs" / "TOOL_TABLE.md"

_TOOL_DEC = re.compile(r"@mcp\.tool\(")
_PROMPT_DEC = re.compile(r"@mcp\.prompt\(")
_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")


def _names_after(decorator: re.Pattern, text: str) -> list[str]:
    names: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if decorator.search(line):
            for j in range(i + 1, min(i + 6, len(lines))):
                m = _DEF.match(lines[j])
                if m:
                    names.append(m.group(1))
                    break
    return names


def collect() -> dict:
    by_module: dict[str, list[str]] = {}
    prompts: list[str] = []
    for path in sorted(PKG.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        tools = _names_after(_TOOL_DEC, text)
        if tools:
            label = f"tools/{path.stem}" if path.parent.name == "tools" else path.stem
            by_module.setdefault(label, []).extend(tools)
        prompts.extend(_names_after(_PROMPT_DEC, text))
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
        if str(data["total_tools"]) not in readme:
            print(f"STALE: README does not mention current tool count "
                  f"({data['total_tools']}). Run generate_tool_table.py and update README.",
                  file=sys.stderr)
            return 1
        print(f"OK: README references current tool count ({data['total_tools']}).")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render_markdown(data), encoding="utf-8")
    print(summary)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
