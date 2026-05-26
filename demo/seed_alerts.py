#!/usr/bin/env python3
"""Demo seed script — injects realistic sample Wazuh alerts into the Indexer.

Generates a week of alert history across multiple agents, covering:
  - SSH brute force from known malicious IPs
  - Malware detection via FIM
  - Privilege escalation events
  - Web application attacks (SQLi, XSS)
  - Successful logins from unusual locations
  - CVE-mapped vulnerability alerts
  - MITRE ATT&CK technique coverage

Run: docker compose --profile seed run seed
  or: INDEXER_URL=https://localhost:9200 INDEXER_USER=admin INDEXER_PASS=pass python seed_alerts.py
"""
from __future__ import annotations

import json
import os
import random
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from typing import Any

INDEXER_URL  = os.getenv("INDEXER_URL",  "https://localhost:9200")
INDEXER_USER = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASS", "SecureDemo@123")
INDEX        = "wazuh-alerts-4.x-demo"

# ── Sample data pools ─────────────────────────────────────────────────────────
AGENTS = [
    {"id": "001", "name": "web-server-01",  "ip": "10.0.1.10", "os": "Ubuntu 22.04"},
    {"id": "002", "name": "db-server-01",   "ip": "10.0.1.20", "os": "CentOS 7"},
    {"id": "003", "name": "auth-server",    "ip": "10.0.1.30", "os": "Ubuntu 20.04"},
    {"id": "004", "name": "jump-host",      "ip": "10.0.1.40", "os": "Debian 11"},
    {"id": "005", "name": "win-workstation","ip": "10.0.2.50", "os": "Windows 11"},
]

MALICIOUS_IPS = [
    ("185.234.219.30", "Russia",        "Malicious Cloud AS"),
    ("45.142.212.100", "Netherlands",   "Bulletproof Hosting"),
    ("103.75.189.10",  "China",         "Known APT Infrastructure"),
    ("194.165.16.76",  "Ukraine",       "Botnet C2"),
    ("5.188.206.14",   "Russia",        "Spam/Brute Force Source"),
]

ALERT_TEMPLATES: list[dict[str, Any]] = [
    # SSH Brute Force
    {
        "rule": {"id": "5710", "level": 10, "description": "Multiple SSH login failures",
                 "groups": ["authentication_failed", "sshd"],
                 "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
        "data": {"srcuser": random.choice(["root","admin","ubuntu","pi"]),
                 "dstuser": "root", "protocol": "ssh"},
        "weight": 30,
    },
    # Successful login after failures
    {
        "rule": {"id": "5715", "level": 8, "description": "SSH login success after multiple failures",
                 "groups": ["authentication_success", "sshd"],
                 "mitre": {"id": ["T1078"], "tactic": ["Persistence"]}},
        "weight": 5,
    },
    # FIM — malware drop
    {
        "rule": {"id": "550", "level": 13, "description": "File added to system directory",
                 "groups": ["syscheck", "fim"],
                 "mitre": {"id": ["T1105"], "tactic": ["Command and Control"]}},
        "data": {"path": "/tmp/.x11unix/update", "md5": "d41d8cd98f00b204e9800998ecf8427e"},
        "weight": 3,
    },
    # Privilege escalation
    {
        "rule": {"id": "5402", "level": 12, "description": "Successful sudo execution",
                 "groups": ["authentication_success", "sudo"],
                 "mitre": {"id": ["T1548"], "tactic": ["Privilege Escalation"]}},
        "data": {"srcuser": "ubuntu", "dstuser": "root"},
        "weight": 8,
    },
    # Web attack — SQLi
    {
        "rule": {"id": "31106", "level": 10, "description": "SQL injection attempt detected",
                 "groups": ["web", "attack", "sql_injection"],
                 "mitre": {"id": ["T1190"], "tactic": ["Initial Access"]}},
        "data": {"url": "/login.php?id=1' OR '1'='1", "method": "GET"},
        "weight": 15,
    },
    # Rootkit detection
    {
        "rule": {"id": "510", "level": 14, "description": "Rootkit: Hidden file detected",
                 "groups": ["rootcheck", "rootkit"],
                 "mitre": {"id": ["T1014"], "tactic": ["Defense Evasion"]}},
        "weight": 1,
    },
    # Lateral movement
    {
        "rule": {"id": "5501", "level": 9, "description": "Multiple authentication failures on different hosts",
                 "groups": ["authentication_failed", "win_ms-wef"],
                 "mitre": {"id": ["T1021"], "tactic": ["Lateral Movement"]}},
        "weight": 10,
    },
    # Vulnerability
    {
        "rule": {"id": "23501", "level": 7, "description": "CVE-2024-3094: XZ Utils backdoor vulnerability",
                 "groups": ["vulnerability-detector"],
                 "mitre": {"id": ["T1195"], "tactic": ["Initial Access"]}},
        "data": {"cve": "CVE-2024-3094", "cvss": 10.0, "package": "xz-utils"},
        "weight": 5,
    },
    # High severity critical alert
    {
        "rule": {"id": "40101", "level": 15, "description": "Ransomware behaviour detected: mass file encryption",
                 "groups": ["malware", "ransomware"],
                 "mitre": {"id": ["T1486"], "tactic": ["Impact"]}},
        "weight": 1,
    },
    # Low-level noise
    {
        "rule": {"id": "1002", "level": 3, "description": "Unknown problem somewhere in the system",
                 "groups": ["syslog"],
                 "mitre": {}},
        "weight": 40,
    },
]

# Pre-compute cumulative weights
_total_weight = sum(t["weight"] for t in ALERT_TEMPLATES)


def _pick_template() -> dict:
    r = random.uniform(0, _total_weight)
    cumulative = 0
    for tmpl in ALERT_TEMPLATES:
        cumulative += tmpl["weight"]
        if r <= cumulative:
            return tmpl
    return ALERT_TEMPLATES[-1]


def _make_alert(ts: datetime) -> dict:
    agent = random.choice(AGENTS)
    tmpl = _pick_template()
    malicious = random.choice(MALICIOUS_IPS)

    data = dict(tmpl.get("data", {}))
    # Randomise per-alert fields
    if "srcuser" in data:
        data["srcuser"] = random.choice(["root","admin","ubuntu","pi","oracle","postgres"])
    data["srcip"] = malicious[0]
    data["srcport"] = str(random.randint(1024, 65535))

    rule = dict(tmpl["rule"])
    # Slight jitter on level for variety
    rule["level"] = max(1, min(15, rule["level"] + random.randint(-1, 1)))

    full_log = (
        f"{ts.strftime('%b %d %H:%M:%S')} {agent['name']} sshd[{random.randint(1000,9999)}]: "
        f"{rule['description']} from {malicious[0]} port {data['srcport']}"
    )

    return {
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "id": f"demo-{int(ts.timestamp())}-{random.randint(1000,9999)}",
        "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"],
                  "version": "4.7.3"},
        "manager": {"name": "wazuh-manager"},
        "cluster": {"name": "demo", "node": "wazuh-manager"},
        "rule": rule,
        "data": data,
        "GeoLocation": {
            "country_name": malicious[1],
            "city_name": f"Demo City, {malicious[1]}",
        },
        "full_log": full_log,
        "predecoder": {"program_name": "sshd", "hostname": agent["name"]},
        "location": f"/var/log/auth.log",
        "decoder": {"name": "sshd"},
    }


def _bulk_index(docs: list[dict]) -> None:
    """Send bulk index request to OpenSearch."""
    lines = []
    for doc in docs:
        doc_id = doc.pop("id", None)
        meta = {"index": {"_index": INDEX}}
        if doc_id:
            meta["index"]["_id"] = doc_id
        lines.append(json.dumps(meta))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    import base64
    token = base64.b64encode(f"{INDEXER_USER}:{INDEXER_PASS}".encode()).decode()
    req = urllib.request.Request(
        f"{INDEXER_URL}/_bulk",
        data=body.encode(),
        headers={
            "Content-Type": "application/x-ndjson",
            "Authorization": f"Basic {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        result = json.loads(resp.read())
        errors = result.get("errors", False)
        if errors:
            print(f"  ⚠ Bulk index had errors: {result['items'][0]}")


def main() -> None:
    print("Wazuh MCP Demo — Seeding sample alerts")
    print(f"  Target: {INDEXER_URL}/{INDEX}")

    # Wait for indexer to be ready
    print("  Waiting for indexer…")
    for attempt in range(30):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            import base64
            token = base64.b64encode(f"{INDEXER_USER}:{INDEXER_PASS}".encode()).decode()
            req = urllib.request.Request(
                f"{INDEXER_URL}/_cluster/health",
                headers={"Authorization": f"Basic {token}"},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
                health = json.loads(r.read())
                if health.get("status") in ("green", "yellow"):
                    print(f"  ✓ Indexer ready (cluster: {health['status']})")
                    break
        except Exception:
            pass
        print(f"  Attempt {attempt+1}/30 — not ready yet, retrying…")
        time.sleep(5)
    else:
        print("  ✗ Indexer not ready after 150s. Aborting.")
        raise SystemExit(1)

    # Generate 7 days of alerts with realistic volume patterns
    now = datetime.now(timezone.utc)
    total_docs = 0
    batch: list[dict] = []

    print("  Generating 7 days of alert history…")
    for day_offset in range(7, -1, -1):
        day = now - timedelta(days=day_offset)
        # Volume: higher during business hours, spike events
        base_per_hour = random.randint(15, 40)
        spike_hour = random.randint(2, 22)

        for hour in range(24):
            volume = base_per_hour
            if hour == spike_hour:
                volume = base_per_hour * random.randint(3, 8)  # attack spike
            elif 0 <= hour <= 6:
                volume = max(5, base_per_hour // 3)             # quiet overnight

            for _ in range(volume):
                ts = day.replace(hour=hour, minute=random.randint(0,59),
                                  second=random.randint(0,59), microsecond=0)
                batch.append(_make_alert(ts))
                total_docs += 1

                if len(batch) >= 200:
                    _bulk_index(batch)
                    batch.clear()

    if batch:
        _bulk_index(batch)

    print(f"  ✓ Seeded {total_docs} alerts across {len(AGENTS)} agents")
    print()
    print("  Next steps:")
    print("  1. Open the SOC Dashboard: dashboard/index.html")
    print("  2. Or connect Claude Desktop to http://localhost:8000")
    print("  3. Ask Claude: 'Summarise the last 24 hours of alerts'")


if __name__ == "__main__":
    main()
