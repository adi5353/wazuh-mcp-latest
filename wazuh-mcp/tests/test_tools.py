import pytest
import json
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_preview_cdb_list_impact_dry_run():
    """preview_cdb_list_impact should return estimated impact without writes."""
    mock_response = {
        "hits": {"total": {"value": 42}, "hits": []},
        "aggregations": {
            "by_rule": {"buckets": [{"key": "SSH brute force", "doc_count": 40}]},
            "by_agent": {"buckets": [{"key": "Server1", "doc_count": 42}]},
        },
    }
    with patch("wazuh_mcp.server.WazuhIndexerClient") as MockClient:
        MockClient.return_value.search = AsyncMock(return_value=mock_response)
        from wazuh_mcp.server import preview_cdb_list_impact
        result = json.loads(await preview_cdb_list_impact(ip="1.2.3.4", hours=24))
        assert result["ip"] == "1.2.3.4"
        assert result["alerts_last_n_hours"] == 42


@pytest.mark.asyncio
async def test_bulk_suppress_rule_dry_run():
    """bulk_suppress_rule should NOT write when dry_run=True."""
    mock_response = {"hits": {"total": {"value": 15}, "hits": []}}
    with patch("wazuh_mcp.server.WazuhIndexerClient") as MockClient:
        MockClient.return_value.search = AsyncMock(return_value=mock_response)
        from wazuh_mcp.server import bulk_suppress_rule
        result = json.loads(await bulk_suppress_rule(rule_id=5710, reason="test", dry_run=True))
        assert result["dry_run"] is True
        assert result["alerts_that_would_be_tagged"] == 15
