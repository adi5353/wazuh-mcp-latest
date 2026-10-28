<!--
Thanks for contributing! Keep PRs focused. See CONTRIBUTING.md for the full guide.
Do NOT include real credentials, tokens, or PII in the diff, tests, or logs.
-->

## What & why

<!-- What does this change and why? Link any related issue: "Closes #123". -->

## Type of change

- [ ] `fix` — bug fix
- [ ] `feat` — new tool or capability
- [ ] `refactor` / `perf` — no behaviour change
- [ ] `docs` / `ci` — non-code

## Checklist

<!-- These mirror CONTRIBUTING.md. Gates ratchet up — do not lower one to make CI pass. -->

- [ ] New/changed tools call `require_role()` with the correct minimum role
- [ ] Tools have a docstring (one-line summary + `Args:` section)
- [ ] Tests added/extended assert **real behaviour** (not just `isinstance(x, dict)`); breadth-only mock checks use the `smoke` marker
- [ ] `make lint` passes (ruff + mypy)
- [ ] `make security` passes (no new bandit findings above medium)
- [ ] `make test` passes; coverage gate not lowered
- [ ] If tool/module count changed: ran `python scripts/generate_tool_table.py` so README counts stay in sync
- [ ] Entry added to `CHANGELOG.md` under `[Unreleased]`
