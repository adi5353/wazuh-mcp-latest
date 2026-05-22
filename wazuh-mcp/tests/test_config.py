from wazuh_mcp.config import Config

def test_config_loads():
    cfg = Config.from_env()
    assert cfg.wazuh_host.startswith("https://")
    assert cfg.wazuh_user == "wazuh-mcp"
    assert cfg.allow_writes is False

def test_config_defaults():
    cfg = Config.from_env()
    assert cfg.request_timeout == 30
    assert cfg.verify_ssl is False
