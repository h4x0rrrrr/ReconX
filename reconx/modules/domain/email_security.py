"""Email Security Gateway (SEG) classification and DMARC / SPF defense posture auditing."""
from __future__ import annotations
import re
from typing import Any, Mapping

KNOWN_SEG_PATTERNS = [
    (re.compile(r"\.pphosted\.com|\.proofpoint\.com", re.I), "Proofpoint Enterprise"),
    (re.compile(r"\.mimecast\.com", re.I), "Mimecast Email Security"),
    (re.compile(r"mail\.protection\.outlook\.com", re.I), "Microsoft Defender for Office 365"),
    (re.compile(r"aspmx.*\.google\.com|googlemail\.com", re.I), "Google Workspace"),
    (re.compile(r"\.barracudanetworks\.com", re.I), "Barracuda Email Security"),
    (re.compile(r"\.iphmx\.com|\.ironport\.com", re.I), "Cisco IronPort / ESA"),
    (re.compile(r"\.trendmicro\.com", re.I), "Trend Micro Email Security"),
    (re.compile(r"\.sophos\.com", re.I), "Sophos Email Security"),
    (re.compile(r"\.mailcontrol\.com", re.I), "Forcepoint Email Security"),
    (re.compile(r"\.zoho\.com", re.I), "Zoho Mail"),
]

def audit_email_security(
    domain: str,
    dns_records: Mapping[str, list[dict[str, str] | str]],
) -> dict[str, Any]:
    """Analyze MX, DMARC, and SPF DNS records to evaluate inbound mail defenses and spoofing resilience."""
    clean_domain = domain.strip().lower().rstrip(".")

    # 1. Parse MX Records & Identify Gateway
    mx_entries = dns_records.get("MX", [])
    mx_hosts: list[str] = []
    for item in mx_entries:
        val = item.get("value", "") if isinstance(item, dict) else str(item)
        val = val.strip().lower().rstrip(".")
        # MX records often have preference, e.g. "10 mail.example.com"
        parts = val.split()
        host = parts[-1] if parts else val
        if host:
            mx_hosts.append(host)

    seg_vendor = "No MX Records"
    if mx_hosts:
        detected_vendor = None
        for host in mx_hosts:
            for pattern, name in KNOWN_SEG_PATTERNS:
                if pattern.search(host):
                    detected_vendor = name
                    break
            if detected_vendor:
                break
        seg_vendor = detected_vendor or "Custom / Self-Hosted Mail Server"

    # 2. Parse DMARC Record
    dmarc_entries = dns_records.get("DMARC", [])
    raw_dmarc = ""
    for item in dmarc_entries:
        val = item.get("value", "") if isinstance(item, dict) else str(item)
        if "v=dmarc1" in val.lower():
            raw_dmarc = val.strip().strip('"')
            break

    dmarc_info: dict[str, Any] = {
        "present": bool(raw_dmarc),
        "record": raw_dmarc or None,
        "policy": "missing",
        "subdomain_policy": None,
        "pct": 100,
        "rua": None,
        "spoofing_risk": "High",
        "compliance": "Unprotected against domain spoofing (No DMARC record found)",
    }

    if raw_dmarc:
        p_match = re.search(r"\bp=([a-z]+)", raw_dmarc, re.I)
        policy = p_match.group(1).lower() if p_match else "none"
        dmarc_info["policy"] = policy

        sp_match = re.search(r"\bsp=([a-z]+)", raw_dmarc, re.I)
        if sp_match:
            dmarc_info["subdomain_policy"] = sp_match.group(1).lower()

        pct_match = re.search(r"\bpct=(\d+)", raw_dmarc, re.I)
        if pct_match:
            try:
                dmarc_info["pct"] = int(pct_match.group(1))
            except ValueError:
                pass

        rua_match = re.search(r"\brua=([^;]+)", raw_dmarc, re.I)
        if rua_match:
            dmarc_info["rua"] = rua_match.group(1).strip()

        if policy == "reject":
            dmarc_info["spoofing_risk"] = "Low"
            dmarc_info["compliance"] = "Strict Anti-Spoofing (p=reject, unauthorized mail rejected)"
        elif policy == "quarantine":
            dmarc_info["spoofing_risk"] = "Medium"
            dmarc_info["compliance"] = "Filtered Anti-Spoofing (p=quarantine, unauthorized mail quarantined)"
        else:
            dmarc_info["spoofing_risk"] = "High"
            dmarc_info["compliance"] = "Monitoring Only (p=none, domain is susceptible to direct email spoofing)"

    # 3. Parse SPF Record
    spf_entries = dns_records.get("SPF", [])
    if not spf_entries:
        txt_entries = dns_records.get("TXT", [])
        spf_entries = [x for x in txt_entries if "v=spf1" in (x.get("value", "") if isinstance(x, dict) else str(x)).lower()]

    raw_spf = ""
    for item in spf_entries:
        val = item.get("value", "") if isinstance(item, dict) else str(item)
        if "v=spf1" in val.lower():
            raw_spf = val.strip().strip('"')
            break

    spf_info: dict[str, Any] = {
        "present": bool(raw_spf),
        "record": raw_spf or None,
        "qualifier": None,
        "includes": [],
    }

    if raw_spf:
        qual_match = re.search(r"([+~?-]all)", raw_spf, re.I)
        if qual_match:
            spf_info["qualifier"] = qual_match.group(1).lower()
        spf_info["includes"] = re.findall(r"include:([^\s]+)", raw_spf, re.I)

    return {
        "domain": clean_domain,
        "seg_vendor": seg_vendor,
        "mx_hosts": mx_hosts,
        "dmarc": dmarc_info,
        "spf": spf_info,
        "source": "email_security_audit",
    }
