import httpx

# Lightweight MITRE ATT&CK technique ID → name/tactic mapping (offline, no API calls)
# Covers the most common technique IDs seen in Wazuh deployments
MITRE_TECHNIQUES = {
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1569": {"name": "System Services", "tactic": "Execution"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
}

def enrich_mitre_ids(technique_ids: list) -> list:
    """Map MITRE technique IDs to names and tactics."""
    enriched = []
    for tid in technique_ids:
        base_id = tid.split(".")[0]  # handle subtechniques like T1059.001
        info = MITRE_TECHNIQUES.get(base_id, {})
        enriched.append({
            "id": tid,
            "name": info.get("name", "Unknown Technique"),
            "tactic": info.get("tactic", "Unknown"),
        })
    return enriched

async def geoip_lookup(ip: str) -> dict:
    """
    Look up geolocation for an IP using ip-api.com (free, no key needed, 45 req/min).
    Returns country, city, ISP, and ASN. Falls back gracefully on error.
    """
    if ip in ("", "127.0.0.1", "::1") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return {"ip": ip, "geo": "private/local"}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,as,status")
            data = r.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "asn": data.get("as", ""),
                }
    except Exception:
        pass
    return {"ip": ip, "geo": "lookup_failed"}
