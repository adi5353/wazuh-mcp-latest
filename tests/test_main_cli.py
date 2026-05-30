"""Tests for the ``python -m wazuh_mcp`` CLI: init wizard, verify, dispatch."""
from __future__ import annotations

import builtins
import getpass as _getpass
import os

import pytest

import wazuh_mcp.__main__ as cli


@pytest.fixture(autouse=True)
def _silence_print(monkeypatch):
    """The wizard prints Unicode box-drawing/✓ glyphs that a Windows cp1252
    captured stdout can't encode. Silence print so tests are platform-agnostic;
    we assert on the written .env file, not on console output."""
    monkeypatch.setattr(builtins, "print", lambda *a, **k: None)
    yield


def _feed(monkeypatch, inputs, secrets):
    it_in = iter(inputs)
    it_sec = iter(secrets)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it_in))
    monkeypatch.setattr(_getpass, "getpass", lambda *a, **k: next(it_sec))


def _read_env(tmp_path):
    return (tmp_path / ".env").read_text(encoding="utf-8")


class TestInitWizard:
    def test_selfhosted_http(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _feed(
            monkeypatch,
            inputs=["1", "https://m:55000", "wazuh-wui", "https://m:9200", "ro",
                    "http", "0.0.0.0", "8000", "y", ""],
            secrets=["mgrpw", "idxpw", "apikey", "vtkey", "abkey"],
        )
        cli._cmd_init()
        env = _read_env(tmp_path)
        assert "WAZUH_HOST=https://m:55000" in env
        assert "WAZUH_MCP_API_KEY=apikey" in env
        assert "VIRUSTOTAL_API_KEY=vtkey" in env
        # 0o600 perms when supported (skip the mode check on Windows).
        if os.name != "nt":
            assert (os.stat(tmp_path / ".env").st_mode & 0o777) == 0o600

    def test_cloud_stdio(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _feed(
            monkeypatch,
            inputs=["2", "https://x.cloud.wazuh.com:55000", "stdio", "n", ""],
            secrets=["ckey", "cidxpw", "", ""],
        )
        cli._cmd_init()
        env = _read_env(tmp_path)
        assert "WAZUH_CLOUD=true" in env
        assert "WAZUH_VERIFY_SSL=false" in env

    def test_mssp(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _feed(
            monkeypatch,
            inputs=["3", "client-a", "https://a:55000", "wazuh-wui", "https://a:9200",
                    "", "stdio", "y", ""],
            secrets=["pw", "idxpw", "vt", "ab"],
        )
        cli._cmd_init()
        env = _read_env(tmp_path)
        assert "WAZUH_INSTANCES=" in env
        assert "client-a" in env

    def test_mssp_empty_falls_back(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _feed(
            monkeypatch,
            inputs=["3", "", "https://m:55000", "wazuh-wui", "https://m:9200", "ro",
                    "stdio", "y", ""],
            secrets=["mgrpw", "idxpw", "", ""],
        )
        cli._cmd_init()
        env = _read_env(tmp_path)
        assert "WAZUH_HOST=https://m:55000" in env

    def test_overwrite_abort(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("EXISTING=1", encoding="utf-8")
        _feed(monkeypatch, inputs=["n"], secrets=[])
        with pytest.raises(SystemExit):
            cli._cmd_init()
        assert "EXISTING=1" in _read_env(tmp_path)


class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return self._data


class _FakeClient:
    def __init__(self, manager_status=200, indexer_status=200):
        self._m = manager_status
        self._i = indexer_status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        if "_cluster/health" in url:
            return _Resp(self._i, {"status": "green", "number_of_nodes": 3})
        return _Resp(self._m, {"data": {"api_version": "4.9.0"}})


class TestVerify:
    def test_verify_all_ok(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("WAZUH_HOST", "https://127.0.0.1:55000")
        monkeypatch.setenv("WAZUH_USER", "u")
        monkeypatch.setenv("WAZUH_PASS", "p")
        monkeypatch.setenv("WAZUH_INDEXER_HOST", "https://127.0.0.1:9200")
        monkeypatch.setenv("WAZUH_INDEXER_PASS", "p")
        import httpx
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _FakeClient())
        cli._cmd_verify()  # all ✓ → no SystemExit

    def test_verify_failure_exits(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("WAZUH_HOST", "https://127.0.0.1:55000")
        monkeypatch.setenv("WAZUH_USER", "u")
        monkeypatch.setenv("WAZUH_PASS", "p")
        monkeypatch.setenv("WAZUH_INDEXER_HOST", "https://127.0.0.1:9200")
        monkeypatch.setenv("WAZUH_INDEXER_PASS", "p")
        import httpx
        monkeypatch.setattr(httpx, "AsyncClient",
                            lambda *a, **k: _FakeClient(manager_status=500, indexer_status=503))
        with pytest.raises(SystemExit):
            cli._cmd_verify()


class TestDispatch:
    def test_main_init_dispatch(self, monkeypatch):
        called = {"n": 0}
        monkeypatch.setattr(cli, "_cmd_init", lambda: called.__setitem__("n", 1))
        monkeypatch.setattr(cli.sys, "argv", ["wazuh-mcp", "init"])
        cli.main()
        assert called["n"] == 1

    def test_main_verify_dispatch(self, monkeypatch):
        called = {"n": 0}
        monkeypatch.setattr(cli, "_cmd_verify", lambda: called.__setitem__("n", 1))
        monkeypatch.setattr(cli.sys, "argv", ["wazuh-mcp", "verify"])
        cli.main()
        assert called["n"] == 1

    def test_main_default_starts_server(self, monkeypatch):
        import wazuh_mcp.server as server
        called = {"n": 0}
        monkeypatch.setattr(server, "main", lambda: called.__setitem__("n", 1))
        monkeypatch.setattr(cli.sys, "argv", ["wazuh-mcp"])
        cli.main()
        assert called["n"] == 1
