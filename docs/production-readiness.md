# Production Readiness

This is the **definition of done** for this project. Its purpose is to end the
cycle where "is it production-ready?" has no answer, so every review surfaces
"more flaws" indefinitely. Production-readiness here is **incremental and
declarable**: certify a small core against this checklist, ship it, then expand
the certified set one slice at a time.

> **The honesty rule.** Every gate below must *verify behaviour*, not produce a
> green light that checks nothing. Never weaken a gate to make CI pass — ratchet
> it up. This repo has already had three hollow gates (coverage satisfied by
> padding, mypy skipping untyped bodies, an integration job running zero tests);
> the anti-patterns section exists so they don't come back.

---

## 0. Honest baseline (2026-05-31)

What is actually true today — update this block whenever the numbers move.

| Gate | State | Notes |
|------|-------|-------|
| Coverage (behaviour-only) | **~49%** | Padding suites quarantined as `smoke`; gate `--cov-fail-under=48` in `pyproject.toml`. Ratchet up. |
| Type checking | **real** | `[tool.mypy] check_untyped_defs = true`; CI `mypy` is blocking. |
| Lint | enforced | `ruff` blocking in CI. |
| SAST / deps | enforced | `bandit`, `pip-audit` blocking in CI. |
| Container scan | enforced | Trivy HIGH/CRITICAL blocking; SBOM published. |
| Live integration | **harness exists, first run unvalidated** | `tests/integration/` + `Integration (live Wazuh)` CI job. Must go green once against a real stack. |
| Definition of done | **this document** | Core scope not yet certified. |

**Not yet done / known gaps:** real coverage is below half the codebase; the
live integration run has not yet passed against a real Wazuh; the core scope
(§4) has not been formally certified.

---

## 1. Per-tool / per-module certification

A tool or module is production-ready only when **every** box is checked *for it*.
Do not mark a tool ready on the strength of suite-wide numbers.

- [ ] **Behaviour tests** assert on real outputs/side-effects — not `isinstance(x, dict)` against mocks. (Padding lives under the `smoke` marker and must not count.)
- [ ] **At least one live integration test** exercises it against a real Wazuh Manager/Indexer (`tests/integration/`).
- [ ] **Client-layer contract** is covered by a test backed by a recorded real API response (catches Wazuh API drift).
- [ ] **RBAC** enforced at the entry point and tested for every mutating action (`wazuh_mcp/rbac.py`, `identity.py`).
- [ ] **Input validation + output sanitization** tested with adversarial inputs (`validators.py`, `input_sanitizer.py`, `audit.py`).
- [ ] **Failure modes** (timeout, auth failure, empty result, backend 5xx) are handled *and tested* — not just the happy path.
- [ ] **Types**: `mypy` clean with `check_untyped_defs`; public functions annotated.
- [ ] **Docs**: the tool's purpose, required role, and arguments are documented (`docs/TOOL_TABLE.md`).
- [ ] **No open `fix/*` regression** for this module in the recent history.

---

## 2. System-level gates

These apply to the deployment as a whole and must hold before any release.

### Security
- [ ] No secrets in source, logs, or audit trail — verified by `detect-secrets` with a committed `.secrets.baseline`.
- [ ] Credentials resolved only via env or the secrets backend (`secrets_backend.py`); `Config.redacted()` used wherever config is logged.
- [ ] RBAC default-deny: unknown/insufficient roles are rejected, not defaulted up (`rbac.py`).
- [ ] Prompt-injection + output sanitization enforced at the MCP layer (`input_sanitizer.py`, `audit.py`).
- [ ] TLS/mTLS verified on; `WAZUH_VERIFY_SSL=true` in production (`tls_config.py`).
- [ ] Rate limiting and security headers active (`rate_limit.py`, `security_headers.py`).
- [ ] Audit log integrity (HMAC signing) enabled and verifiable.

### Reliability & operability
- [ ] Retry/backoff and circuit breakers exercised by tests (`circuit_breaker.py`, client retry paths).
- [ ] Health endpoint and Prometheus metrics return real data (`/metrics`, server metrics tools).
- [ ] Graceful shutdown releases connection pools (`WazuhClient.aclose`, `WazuhIndexer.aclose`).
- [ ] Structured logging with no credential leakage.

### Build & deploy
- [ ] Docker image builds, runs non-root, read-only FS, all caps dropped (`Dockerfile`, `compose.yaml`).
- [ ] Dependencies pinned and reproducible (`requirements.lock`); Trivy clean for HIGH/CRITICAL.
- [ ] Deployment documented and tested (compose / systemd / pip) in `README.md`.

### CI quality (the gates themselves)
- [ ] Coverage gate measures behaviour tests only and trends **up** over time.
- [ ] `mypy` blocking with `check_untyped_defs`.
- [ ] The `Integration (live Wazuh)` job has passed at least once against a real stack.
- [ ] No job is faked, `continue-on-error`, or `|| echo`-swallowed to appear green.

---

## 3. Release gate

Before tagging a version, confirm in order:

1. All CI jobs green **and** meaningful (spot-check that the integration job actually ran, not skipped).
2. The certified core scope (§4) passes its full per-tool checklist (§1).
3. `docs/production-readiness.md` baseline (§0) updated with current honest numbers.
4. `CHANGELOG`/README version notes reflect what actually changed.
5. A manual smoke test against a real Wazuh per `docs/testing-guide.md`.

---

## 4. Core scope to certify first

Freeze feature growth and certify this set before expanding. Everything outside
it is **beta** until it earns the same checklist.

**Security spine:** `rbac.py`, `identity.py`, `input_sanitizer.py`, `audit.py`,
`config.py`, `secrets_backend.py`, `wazuh_client.py`, `wazuh_indexer.py`.

**Core tools:** `tools/alerts.py`, `tools/agents.py`, `tools/vulnerabilities.py`,
`tools/fim.py` (adjust to the tools you actually support first).

Once these are green on §1 + §2, the core is production-ready. Ship it, then
unfreeze the next slice and repeat.

---

## Anti-patterns — never reintroduce

- ❌ Tests that exist only to raise the coverage number (assert-nothing, mock-everything). Mark genuine breadth checks `smoke`; they never gate.
- ❌ Lowering a gate (coverage %, mypy strictness) to make CI pass. Gates ratchet up.
- ❌ `mypy` without `check_untyped_defs` — it reports "Success" while checking almost nothing.
- ❌ CI jobs that pass without doing work (`|| echo`, empty service stubs, blanket `continue-on-error`).
- ❌ Wall-clock timing assertions gating CI — they flake. Keep them under the `perf` marker, non-gating.
- ❌ Large, sprawling commits. Small, single-concern PRs with the tests that cover them.
