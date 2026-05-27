"""Agent onboarding tools — enrollment command generation, never-connected agents, health checklist."""
from __future__ import annotations
from ..tool_context import ToolContext

import os


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap

    @mcp.tool()
    async def generate_enrollment_command(
        agent_name: str,
        os_type: str,
        group: str = "default",
        wazuh_manager_ip: str | None = None,
        registration_password: str | None = None,
    ) -> dict:
        """Generate the exact Wazuh agent installation command for a given OS.

        os_type: ubuntu | debian | centos | rhel | amazon_linux | windows | macos
        group: agent group to enroll into (default: 'default')
        wazuh_manager_ip: override the manager IP shown in the command
                          (defaults to WAZUH_HOST env var, protocol stripped)
        Supports Wazuh 4.x package URLs.
        """
        raw_host = wazuh_manager_ip or cfg.manager_host
        manager_ip = raw_host.replace("https://", "").replace("http://", "").split(":")[0]

        reg_pass = registration_password or os.getenv("WAZUH_REGISTRATION_PASSWORD", "")

        wazuh_ver = "4.7.5"
        try:
            ver_resp = await wz.request("GET", "/")
            wazuh_ver = (
                (ver_resp.get("data") or {}).get("api_version", wazuh_ver)
                or wazuh_ver
            )
        except Exception:
            pass

        os_norm = os_type.lower().replace("-", "_").replace(" ", "_")

        reg_env_linux = f'WAZUH_REGISTRATION_PASSWORD="{reg_pass}" \\\n     ' if reg_pass else ""
        reg_arg_win   = f'WAZUH_REGISTRATION_PASSWORD="{reg_pass}" `\n  ' if reg_pass else ""

        if os_norm in ("ubuntu", "debian"):
            pkg = f"wazuh-agent_{wazuh_ver}-1_amd64.deb"
            url = f"https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/{pkg}"
            command = (
                f"# 1. Download and install\n"
                f"curl -o /tmp/{pkg} \"{url}\"\n"
                f"sudo WAZUH_MANAGER=\"{manager_ip}\" \\\n"
                f"     WAZUH_AGENT_NAME=\"{agent_name}\" \\\n"
                f"     WAZUH_AGENT_GROUP=\"{group}\" \\\n"
                f"     {reg_env_linux}dpkg -i /tmp/{pkg}\n\n"
                f"# 2. Enable and start\n"
                f"sudo systemctl daemon-reload\n"
                f"sudo systemctl enable wazuh-agent\n"
                f"sudo systemctl start wazuh-agent\n\n"
                f"# 3. Verify\n"
                f"sudo systemctl status wazuh-agent"
            )
            notes = f"Package: {pkg}. Alternatively: add the Wazuh apt repo and run `sudo apt-get install wazuh-agent={wazuh_ver}-1`."

        elif os_norm in ("centos", "rhel", "amazon_linux", "fedora", "suse"):
            pkg = f"wazuh-agent-{wazuh_ver}-1.x86_64.rpm"
            url = f"https://packages.wazuh.com/4.x/yum/{pkg}"
            command = (
                f"# 1. Download and install\n"
                f"curl -o /tmp/{pkg} \"{url}\"\n"
                f"sudo WAZUH_MANAGER=\"{manager_ip}\" \\\n"
                f"     WAZUH_AGENT_NAME=\"{agent_name}\" \\\n"
                f"     WAZUH_AGENT_GROUP=\"{group}\" \\\n"
                f"     {reg_env_linux}rpm -ihv /tmp/{pkg}\n\n"
                f"# 2. Enable and start\n"
                f"sudo systemctl daemon-reload\n"
                f"sudo systemctl enable wazuh-agent\n"
                f"sudo systemctl start wazuh-agent\n\n"
                f"# 3. Verify\n"
                f"sudo systemctl status wazuh-agent"
            )
            notes = "Works on CentOS 7/8, RHEL 7/8/9, Amazon Linux 2, Fedora. For SUSE: add Wazuh zypper repo."

        elif os_norm == "windows":
            msi = f"wazuh-agent-{wazuh_ver}-1.msi"
            url = f"https://packages.wazuh.com/4.x/windows/{msi}"
            command = (
                f"# Run in PowerShell as Administrator\n\n"
                f"# 1. Download\n"
                f"Invoke-WebRequest -Uri \"{url}\" -OutFile \"$env:TEMP\\{msi}\"\n\n"
                f"# 2. Install silently\n"
                f"msiexec.exe /i \"$env:TEMP\\{msi}\" /q `\n"
                f"  WAZUH_MANAGER=\"{manager_ip}\" `\n"
                f"  WAZUH_AGENT_NAME=\"{agent_name}\" `\n"
                f"  WAZUH_AGENT_GROUP=\"{group}\" `\n"
                f"  {reg_arg_win}/l*v \"$env:TEMP\\wazuh-install.log\"\n\n"
                f"# 3. Start service\n"
                f"NET START WazuhSvc\n\n"
                f"# 4. Verify\n"
                f"Get-Service WazuhSvc"
            )
            notes = f"MSI: {msi}. Requires .NET 4.5+ and PowerShell 3.0+. Log at %TEMP%\\wazuh-install.log."

        elif os_norm == "macos":
            pkg = f"wazuh-agent-{wazuh_ver}-1.pkg"
            url = f"https://packages.wazuh.com/4.x/macos/{pkg}"
            reg_launchctl = (
                f"sudo launchctl setenv WAZUH_REGISTRATION_PASSWORD \"{reg_pass}\"\n"
                if reg_pass else ""
            )
            command = (
                f"# 1. Download\n"
                f"curl -o /tmp/{pkg} \"{url}\"\n\n"
                f"# 2. Set env vars\n"
                f"sudo launchctl setenv WAZUH_MANAGER \"{manager_ip}\"\n"
                f"sudo launchctl setenv WAZUH_AGENT_NAME \"{agent_name}\"\n"
                f"sudo launchctl setenv WAZUH_AGENT_GROUP \"{group}\"\n"
                f"{reg_launchctl}\n"
                f"# 3. Install\n"
                f"sudo installer -pkg /tmp/{pkg} -target /\n\n"
                f"# 4. Start\n"
                f"sudo /Library/Ossec/bin/wazuh-control start\n\n"
                f"# 5. Verify\n"
                f"sudo /Library/Ossec/bin/wazuh-control status"
            )
            notes = "Requires macOS 10.15+. On Sequoia+: approve extension in System Settings → Privacy & Security."

        else:
            return {
                "error": (
                    f"Unsupported os_type: '{os_type}'. "
                    "Supported: ubuntu, debian, centos, rhel, amazon_linux, windows, macos"
                )
            }

        return {
            "agent_name":      agent_name,
            "os_type":         os_type,
            "manager_ip":      manager_ip,
            "group":           group,
            "wazuh_version":   wazuh_ver,
            "install_command": command,
            "notes":           notes,
            "next_steps": [
                "Run the install_command above as root/Administrator on the target host.",
                f"Verify enrollment: list_agents(status='pending') — look for '{agent_name}'.",
                f"Confirm it comes online: agent_onboarding_checklist(agent_name='{agent_name}').",
            ],
        }

    @mcp.tool()
    async def list_never_connected_agents(limit: int = 50) -> dict:
        """List agents that enrolled in the manager but have never sent a heartbeat.

        Useful for finding failed deployments, stale enrollments, and debugging
        connectivity issues. Includes troubleshooting tips per agent.
        """
        try:
            result = await wz.request(
                "GET", f"/agents?status=never_connected&limit={_cap(limit)}&offset=0"
            )
        except Exception as e:
            return {"error": str(e)}

        items = (result.get("data") or {}).get("affected_items", [])
        total = (result.get("data") or {}).get("total_affected_items", 0)

        if not items:
            return {
                "count":   0,
                "total":   0,
                "agents":  [],
                "message": "No never_connected agents found. All enrolled agents have checked in.",
            }

        formatted = [
            {
                "agent_id":        a.get("id"),
                "agent_name":      a.get("name"),
                "os":              (a.get("os") or {}).get("name", "unknown"),
                "ip":              a.get("ip", "unknown"),
                "registered_date": a.get("dateAdd", "unknown"),
                "groups":          a.get("group", ["default"]),
            }
            for a in items
        ]

        return {
            "count":   len(formatted),
            "total":   total,
            "agents":  formatted,
            "message": (
                f"Found {total} never_connected agent(s). "
                "These enrolled but have not yet sent any events."
            ),
            "troubleshooting_checklist": [
                "1. Verify agent service is running: systemctl status wazuh-agent",
                "2. Check manager IP in /var/ossec/etc/ossec.conf → <server><address>",
                "3. Test connectivity: nc -zv <manager_ip> 1514 && nc -zv <manager_ip> 1515",
                "4. Check manager logs: tail -f /var/ossec/logs/ossec.log | grep <agent_name>",
                "5. Firewall: ensure outbound 1514/UDP (events) and 1515/TCP (registration) are open.",
            ],
        }

    @mcp.tool()
    async def agent_onboarding_checklist(
        agent_id: str | None = None,
        agent_name: str | None = None,
    ) -> dict:
        """Run a 6-point health check on a newly enrolled agent.

        Checks: registered, active status, non-default group, sending events,
        SCA policy loaded, syscollector data available.
        Provide either agent_id (e.g. '005') or agent_name (e.g. 'webserver-01').
        """
        if not agent_id and not agent_name:
            return {"error": "Provide agent_id or agent_name."}

        checks: list[dict] = []
        overall_ok = True

        def _check(name: str, passed: bool, detail: str, warn_only: bool = False) -> dict:
            if passed:
                result = "pass"; icon = "pass"
            elif warn_only:
                result = "warn"; icon = "warn"
            else:
                result = "fail"; icon = "fail"
            return {"check": name, "result": result, "icon": icon, "detail": detail}

        if not agent_id:
            try:
                r = await wz.request("GET", f"/agents?name={agent_name}&limit=1")
                items = (r.get("data") or {}).get("affected_items", [])
                if not items:
                    return {"error": f"No agent found with name '{agent_name}'."}
                agent_id = items[0]["id"]
            except Exception as e:
                return {"error": f"Agent lookup failed: {e}"}

        agent_data: dict = {}
        try:
            r = await wz.request("GET", f"/agents?agents_list={agent_id}")
            items = (r.get("data") or {}).get("affected_items", [])
            if items:
                agent_data = items[0]
                checks.append(_check(
                    "Registered in manager", True,
                    f"Agent ID: {agent_id}, Name: {agent_data.get('name')}",
                ))
            else:
                checks.append(_check("Registered in manager", False, "Agent not found."))
                overall_ok = False
        except Exception as e:
            checks.append(_check("Registered in manager", False, str(e)))
            overall_ok = False

        resolved_name = agent_data.get("name", agent_id)

        status = agent_data.get("status", "unknown")
        active = status == "active"
        if not active:
            overall_ok = False
        checks.append(_check(
            "Agent status is active", active,
            f"Status: {status}" + (
                " — connected and sending heartbeats." if active
                else " — not connected. Verify service is running and firewall allows port 1514."
            ),
        ))

        groups = agent_data.get("group", [])
        in_custom_group = bool(groups) and groups != ["default"]
        checks.append(_check(
            "Assigned to a policy group", in_custom_group,
            f"Groups: {groups}",
            warn_only=True,
        ))

        try:
            event_body = {
                "size": 1,
                "query": {
                    "bool": {
                        "filter": [
                            {"term":  {"agent.id": agent_id}},
                            {"range": {"@timestamp": {"gte": "now-30m"}}},
                        ]
                    }
                },
            }
            er = await idx.search(event_body)
            event_count = er["hits"]["total"]["value"]
            has_events = event_count > 0
            if not has_events:
                overall_ok = False
            checks.append(_check(
                "Sending events (last 30 min)", has_events,
                f"{event_count} alert(s) in last 30 min." if has_events
                else "No events yet. Check ossec.conf <logall> or wait ~5 min after start.",
            ))
        except Exception as e:
            checks.append(_check("Sending events (last 30 min)", False, f"Indexer query failed: {e}"))
            overall_ok = False

        try:
            r = await wz.request("GET", f"/sca/{agent_id}?limit=5")
            policies = (r.get("data") or {}).get("affected_items", [])
            has_sca = len(policies) > 0
            if not has_sca:
                overall_ok = False
            checks.append(_check(
                "SCA policy loaded", has_sca,
                f"{len(policies)} policy(ies): " + ", ".join(p.get("name", "") for p in policies)
                if has_sca else "No SCA policies. Assign agent to a group with SCA configured.",
            ))
        except Exception as e:
            checks.append(_check("SCA policy loaded", False, f"SCA query failed: {e}"))

        try:
            r = await wz.request("GET", f"/syscollector/{agent_id}/packages?limit=1")
            pkg_total = (r.get("data") or {}).get("total_affected_items", 0)
            has_syscollector = pkg_total > 0
            if not has_syscollector:
                overall_ok = False
            checks.append(_check(
                "Syscollector data available", has_syscollector,
                f"{pkg_total} packages indexed." if has_syscollector
                else "Syscollector hasn't run yet. Usually completes within 5 min of first start.",
            ))
        except Exception as e:
            checks.append(_check("Syscollector data available", False, f"Syscollector query failed: {e}"))

        passed   = sum(1 for c in checks if c["result"] == "pass")
        warnings = sum(1 for c in checks if c["result"] == "warn")
        failed   = sum(1 for c in checks if c["result"] == "fail")

        if overall_ok:
            overall = "READY"
        elif failed == 0:
            overall = "READY WITH WARNINGS"
        elif passed >= 4:
            overall = "PARTIAL"
        else:
            overall = "NOT READY"

        return {
            "agent_id":      agent_id,
            "agent_name":    resolved_name,
            "overall":       overall,
            "checks_passed": passed,
            "checks_warned": warnings,
            "checks_failed": failed,
            "checks":        checks,
            "summary": (
                f"Agent '{resolved_name}' onboarding: {passed}/{len(checks)} checks passed. "
                + ("Agent is fully operational." if overall_ok
                   else f"{failed} issue(s) need attention.")
            ),
        }
