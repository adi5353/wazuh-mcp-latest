"""Attribute-Based Access Control (ABAC) for Wazuh MCP.

Extends RBAC with resource-level constraints so that multi-tenant or
department-scoped deployments can restrict which agent groups a role can see.

Configuration (env vars):
    WAZUH_MCP_ALLOWED_GROUPS
        Comma-separated list of agent group names this session may access.
        Empty = no restriction (access all groups).
        Example: WAZUH_MCP_ALLOWED_GROUPS=linux-prod,windows-prod

    WAZUH_MCP_DENIED_GROUPS
        Comma-separated list of agent group names explicitly blocked.
        Checked after allowed list.

    WAZUH_MCP_ALLOWED_AGENTS
        Comma-separated list of specific agent IDs allowed.
        Empty = all agents (subject to group filters above).

Usage in a tool::

    from .abac import check_group_access, filter_agents_by_abac, abac_filter_clause

    # Guard a single group:
    err = check_group_access("windows-prod")
    if err:
        return err

    # Filter a list of agents (dicts with 'group' / 'id' keys):
    visible = filter_agents_by_abac(agents)

    # Inject into an OpenSearch query bool-filter list:
    abac_clauses = abac_filter_clause()
    filters.extend(abac_clauses)
"""
from __future__ import annotations

import os


def _allowed_groups() -> list[str]:
    raw = os.getenv("WAZUH_MCP_ALLOWED_GROUPS", "").strip()
    return [g.strip() for g in raw.split(",") if g.strip()] if raw else []


def _denied_groups() -> list[str]:
    raw = os.getenv("WAZUH_MCP_DENIED_GROUPS", "").strip()
    return [g.strip() for g in raw.split(",") if g.strip()] if raw else []


def _allowed_agents() -> list[str]:
    raw = os.getenv("WAZUH_MCP_ALLOWED_AGENTS", "").strip()
    return [a.strip() for a in raw.split(",") if a.strip()] if raw else []


def abac_enabled() -> bool:
    """Return True if any ABAC constraint is configured."""
    return bool(_allowed_groups() or _denied_groups() or _allowed_agents())


def check_group_access(group_name: str) -> dict | None:
    """Return an error dict if *group_name* is not accessible, else None.

    Call this when a tool operates on a specific agent group.
    """
    allowed = _allowed_groups()
    denied  = _denied_groups()

    if denied and group_name in denied:
        return {
            "error": f"Access denied: group '{group_name}' is in the ABAC deny list.",
            "hint":  "WAZUH_MCP_DENIED_GROUPS restricts access to this agent group.",
        }
    if allowed and group_name not in allowed:
        return {
            "error": f"Access denied: group '{group_name}' is not in your allowed group list.",
            "allowed_groups": allowed,
            "hint":  "Configure WAZUH_MCP_ALLOWED_GROUPS to include this group.",
        }
    return None


def check_agent_access(agent_id: str) -> dict | None:
    """Return an error dict if *agent_id* is not accessible, else None."""
    allowed = _allowed_agents()
    if allowed and agent_id not in allowed:
        return {
            "error": f"Access denied: agent '{agent_id}' is not in your allowed agent list.",
            "hint":  "Configure WAZUH_MCP_ALLOWED_AGENTS to include this agent ID.",
        }
    return None


def abac_filter_clause() -> list[dict]:
    """Return a list of OpenSearch bool-filter clauses enforcing ABAC constraints.

    Inject these into any search query's bool.filter list to automatically
    scope results to the session's allowed groups/agents.

    Example::
        filters = [...your filters...]
        filters.extend(abac_filter_clause())
    """
    clauses: list[dict] = []
    allowed_groups = _allowed_groups()
    denied_groups  = _denied_groups()
    allowed_agents = _allowed_agents()

    if allowed_groups:
        clauses.append({"terms": {"agent.groups": allowed_groups}})

    if denied_groups:
        clauses.append({"bool": {"must_not": [{"terms": {"agent.groups": denied_groups}}]}})

    if allowed_agents:
        clauses.append({"terms": {"agent.id": allowed_agents}})

    return clauses


def filter_agents_by_abac(agents: list[dict]) -> list[dict]:
    """Filter a list of agent dicts to only those accessible under ABAC rules.

    Expects each dict to have at least one of:
      - 'id' key (agent ID string)
      - 'group' or 'groups' key (str or list)

    Returns the filtered list. If ABAC is not configured, returns the list unchanged.
    """
    if not abac_enabled():
        return agents

    allowed_groups = set(_allowed_groups())
    denied_groups  = set(_denied_groups())
    allowed_agents = set(_allowed_agents())

    result = []
    for agent in agents:
        aid = str(agent.get("id", ""))
        raw_groups = agent.get("groups") or agent.get("group") or []
        if isinstance(raw_groups, str):
            raw_groups = [raw_groups]
        grp_set = set(raw_groups)

        if allowed_agents and aid not in allowed_agents:
            continue
        if denied_groups and grp_set & denied_groups:
            continue
        if allowed_groups and not (grp_set & allowed_groups):
            continue

        result.append(agent)

    return result


def abac_status() -> dict:
    """Return the current ABAC configuration — useful for debugging."""
    return {
        "abac_enabled": abac_enabled(),
        "allowed_groups": _allowed_groups(),
        "denied_groups":  _denied_groups(),
        "allowed_agents": _allowed_agents(),
        "hint": (
            "Set WAZUH_MCP_ALLOWED_GROUPS, WAZUH_MCP_DENIED_GROUPS, "
            "or WAZUH_MCP_ALLOWED_AGENTS to scope access."
        ),
    }
