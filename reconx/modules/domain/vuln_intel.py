"""Automated Vulnerability & CVE / CISA KEV Correlation Engine.

Correlates fingerprinted technologies and version numbers against
high-severity CVE advisories and the CISA Known Exploited Vulnerabilities (KEV) catalog.
"""
from __future__ import annotations

import re
from typing import Any

# Curated catalog of high-severity CVEs & CISA Known Exploited Vulnerabilities (KEV)
KNOWN_VULNERABILITY_CATALOG = [
    {
        "tech_pattern": r"apache(?!-coyote)",
        "version_pattern": r"2\.4\.(49|50)",
        "cve": "CVE-2021-41773 / CVE-2021-42013",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cisa_kev": True,
        "title": "Apache HTTP Server Path Traversal and Remote Code Execution",
        "summary": "Path traversal and potential remote code execution via malformed path normalization in Apache 2.4.49/2.4.50.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    },
    {
        "tech_pattern": r"openssh",
        "version_pattern": r"(8\.[5-9]|9\.[0-7])p1",
        "cve": "CVE-2024-6387",
        "severity": "HIGH",
        "cvss": 8.1,
        "cisa_kev": False,
        "title": "OpenSSH 'regreSSHion' Signal Handler Race Condition RCE",
        "summary": "Signal handler race condition in OpenSSH's server (sshd) on glibc-based Linux systems allows unauthenticated remote code execution.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
    },
    {
        "tech_pattern": r"jenkins",
        "version_pattern": r"(2\.(4[0-1][0-9]|42[0-6])|2\.(3[0-9]{2}))",
        "cve": "CVE-2024-23897",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cisa_kev": True,
        "title": "Jenkins CLI Arbitrary File Read and Remote Code Execution",
        "summary": "Args4j parser expands '@' character into file content, allowing unauthenticated arbitrary file read and potential RCE.",
        "advisory": "https://www.jenkins.io/security/advisory/2024-01-24/",
    },
    {
        "tech_pattern": r"microsoft-iis",
        "version_pattern": r"(7\.5|8\.0)",
        "cve": "CVE-2015-1635",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cisa_kev": True,
        "title": "Microsoft Windows HTTP.sys Remote Code Execution (MS15-034)",
        "summary": "Integer overflow vulnerability in HTTP.sys allows remote attackers to execute arbitrary code via malformed Range HTTP request headers.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2015-1635",
    },
    {
        "tech_pattern": r"palo alto|globalprotect",
        "version_pattern": r".*",
        "cve": "CVE-2024-3400",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cisa_kev": True,
        "title": "Palo Alto PAN-OS GlobalProtect Command Injection",
        "summary": "Command injection vulnerability in GlobalProtect feature of PAN-OS allows unauthenticated remote code execution.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
    },
    {
        "tech_pattern": r"citrix|netscaler",
        "version_pattern": r".*",
        "cve": "CVE-2023-4966",
        "severity": "CRITICAL",
        "cvss": 9.4,
        "cisa_kev": True,
        "title": "Citrix Bleed: NetScaler ADC / Gateway Information Disclosure",
        "summary": "Sensitive information disclosure vulnerability allowing session hijacking and token theft on NetScaler ADC and Gateway.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
    },
    {
        "tech_pattern": r"fortinet|fortios|fortigate",
        "version_pattern": r".*",
        "cve": "CVE-2024-21762",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cisa_kev": True,
        "title": "Fortinet FortiOS SSL-VPN Out-of-Bounds Write RCE",
        "summary": "Out-of-bounds write in FortiOS SSL-VPN allows remote unauthenticated attackers to execute arbitrary code via crafted HTTP requests.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
    },
    {
        "tech_pattern": r"phpmyadmin",
        "version_pattern": r"4\.8\.[0-1]",
        "cve": "CVE-2018-12613",
        "severity": "HIGH",
        "cvss": 8.8,
        "cisa_kev": True,
        "title": "phpMyAdmin Local File Inclusion to Remote Code Execution",
        "summary": "LFI flaw in index.php allowed authenticated users to include and execute arbitrary PHP files on the server.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2018-12613",
    },
    {
        "tech_pattern": r"spring boot|spring framework",
        "version_pattern": r".*",
        "cve": "CVE-2022-22965",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cisa_kev": True,
        "title": "Spring4Shell: Spring Framework Remote Code Execution",
        "summary": "Data binding flaw in Spring Core on JDK 9+ allows remote code execution via crafted parameter binding.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
    },
    {
        "tech_pattern": r"microsoft smb",
        "version_pattern": r".*",
        "cve": "CVE-2017-0144",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cisa_kev": True,
        "title": "SMBv1 Remote Code Execution (MS17-010 / EternalBlue)",
        "summary": "Flaw in Microsoft Server Message Block 1.0 (SMBv1) protocol allows remote attackers to execute code via crafted packets.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
    },
    {
        "tech_pattern": r"log4j",
        "version_pattern": r".*",
        "cve": "CVE-2021-44228",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cisa_kev": True,
        "title": "Log4Shell: Apache Log4j2 JNDI Remote Code Execution",
        "summary": "JNDI lookup features in Log4j2 allow unauthenticated remote code execution via log message injection.",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    },
]

def correlate_vulnerabilities(
    technologies: list[str],
    network_services: list[dict[str, Any]] | None = None,
    live_hosts: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Correlate identified technologies and services against known CVE and CISA KEV catalog."""
    correlated: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    # Collect all technology strings and port associations
    candidates: list[tuple[str, str, int | None]] = []

    for t in technologies:
        candidates.append((t, "", None))

    if network_services:
        for s in network_services:
            ip = s.get("ip", "")
            port = s.get("port")
            for t in s.get("technologies", []):
                candidates.append((t, ip, port))

    if live_hosts:
        for h in live_hosts:
            host = h.get("host", "")
            port = h.get("port", 443 if "https://" in h.get("url", "") else 80)
            server = h.get("server", "")
            if server:
                candidates.append((server, host, port))

    for tech_str, host, port in candidates:
        tech_clean = tech_str.strip().lower()

        for entry in KNOWN_VULNERABILITY_CATALOG:
            tech_match = re.search(entry["tech_pattern"], tech_clean, re.I)
            if not tech_match:
                continue

            # Check version match if specified
            ver_match = None
            if entry["version_pattern"] != ".*":
                ver_match = re.search(entry["version_pattern"], tech_clean)
                if not ver_match:
                    continue

            key = f"{entry['cve']}_{tech_clean}_{host}_{port}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            correlated.append({
                "cve": entry["cve"],
                "severity": entry["severity"],
                "cvss": entry["cvss"],
                "cisa_kev": entry["cisa_kev"],
                "title": entry["title"],
                "technology": tech_str,
                "host": host or "Target",
                "port": port,
                "summary": entry["summary"],
                "advisory": entry["advisory"],
            })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    correlated.sort(key=lambda x: (order.get(x["severity"], 4), -x["cvss"]))
    status = f"Completed ({len(correlated)} potential CVE / CISA KEV advisory correlation(s))"
    return correlated, status
