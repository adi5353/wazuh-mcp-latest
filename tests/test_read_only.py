"""Read-only mode: the HTTP-layer guard and tool hiding."""
import httpx
import pytest

from wazuh_mcp import read_only as ro


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.setenv("WAZUH_MCP_READ_ONLY", "true")


def u(path, host="https://m:55000"):
    return httpx.URL(host + path)


@pytest.mark.parametrize("m,p", [
    ("GET", "/agents"), ("POST", "/security/user/authenticate"),
    ("PUT", "/logtest"), ("DELETE", "/logtest/sessions/abc"),
])
def test_manager_allowed(m, p):
    ro.check_manager_request(m, u(p))


@pytest.mark.parametrize("m,p", [
    ("PUT", "/agents/001/restart"), ("PUT", "/active-response"),
    ("PUT", "/lists/files/x"), ("PUT", "/rules/files/x.xml"),
    ("DELETE", "/rootcheck/001"), ("PUT", "/security/users/1"),
    ("POST", "/agents"), ("GET", "/agents/001/key"),
    ("PUT", "/logtest/../rules/files/x"), ("PUT", "/%6cogtest/../agents/001/restart"),
])
def test_manager_blocked(m, p):
    with pytest.raises(ro.ReadOnlyViolation):
        ro.check_manager_request(m, u(p))


def test_indexer_rules():
    ro.check_indexer_request("POST", u("/wazuh-alerts-*/_search", "https://i:9200"))
    ro.check_indexer_request("POST", u("/wazuh-alerts-*/_count", "https://i:9200"))
    ro.check_indexer_request("GET", u("/_cluster/health", "https://i:9200"))
    for m, p in [("POST", "/a/_update_by_query"), ("POST", "/a/_update/1"),
                 ("POST", "/a/_delete_by_query"), ("DELETE", "/a"), ("PUT", "/a/_doc/1"),
                 ("POST", "/_bulk")]:
        with pytest.raises(ro.ReadOnlyViolation):
            ro.check_indexer_request(m, u(p, "https://i:9200"))


def test_disabled_allows_everything(monkeypatch):
    monkeypatch.setenv("WAZUH_MCP_READ_ONLY", "false")
    ro.check_manager_request("PUT", u("/agents/001/restart"))
    ro.check_indexer_request("DELETE", u("/a", "https://i:9200"))


def test_default_is_read_only(monkeypatch):
    monkeypatch.delenv("WAZUH_MCP_READ_ONLY")
    assert ro.is_read_only()


@pytest.mark.asyncio
async def test_upload_blocked():
    from wazuh_mcp.config import Config
    from wazuh_mcp.wazuh_client import WazuhClient
    cfg = Config.from_env()
    c = WazuhClient(cfg)
    with pytest.raises(ro.ReadOnlyViolation):
        await c.upload_xml_file("/rules/files/x.xml", "<group/>")
    await c.aclose()


@pytest.mark.asyncio
async def test_client_hook_blocks_before_network():
    from wazuh_mcp.config import Config
    from wazuh_mcp.wazuh_client import WazuhClient
    c = WazuhClient(Config.from_env())
    c._token = type("T", (), {"get": lambda s: "t"})()
    c._token_expires = 9e12
    with pytest.raises(ro.ReadOnlyViolation):
        await c._request_once("PUT", "/agents/001/restart")
    await c.aclose()


def test_write_tools_not_registered(monkeypatch):
    import importlib, sys
    for k in [k for k in sys.modules if k.startswith("wazuh_mcp.server")]:
        del sys.modules[k]
    server = importlib.import_module("wazuh_mcp.server")
    names = {t for t in server._TOOL_REGISTRY}
    assert not (names & ro.WRITE_TOOLS), names & ro.WRITE_TOOLS
    assert "search_alerts" in names
