"""ASN and IP subnet reverse DNS (PTR) sweep module.

Performs bounded reverse DNS lookups on discovered IP ranges to uncover
internal infrastructure naming conventions and hidden subdomains.
"""
from __future__ import annotations
import asyncio
import ipaddress
import re
from typing import Any
import dns.asyncresolver
import dns.reversename
from reconx.utils.logger import info

INFRA_PATTERNS = {
    "vpn_gateway": re.compile(r"(?:vpn|pulse|remote|gateway|gw|access|bastion|fw|firewall)", re.I),
    "mail_system": re.compile(r"(?:mail|smtp|mx|exchange|webmail|relay|pop3|imap)", re.I),
    "management": re.compile(r"(?:admin|ilo|idrac|bmc|mgmt|cpanel|whm|kibana|grafana|jenkins)", re.I),
    "non_prod": re.compile(r"(?:dev|stage|staging|test|uat|qa|lab|preprod|demo)", re.I),
    "internal_net": re.compile(r"(?:corp|internal|intranet|lan|priv|node|cluster)", re.I),
}

async def _resolve_ptr(ip: str, resolver: dns.asyncresolver.Resolver) -> str | None:
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = await resolver.resolve(rev_name, "PTR", lifetime=2.5)
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        return None

async def sweep_reverse_dns(
    ip_list: list[str],
    cfg: dict[str, Any],
    max_ips: int = 128,
) -> tuple[list[dict[str, Any]], dict[str, list[str]], dict[str, Any]]:
    """Perform bounded PTR sweep across discovered IP addresses.
    
    Returns (ptr_records, classified_infrastructure, source_status).
    """
    valid_ips = set()
    for item in ip_list:
        clean = item.strip()
        try:
            ip_obj = ipaddress.ip_address(clean)
            if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_multicast:
                valid_ips.add(str(ip_obj))
        except ValueError:
            continue

    if not valid_ips:
        return [], {}, {"status": "clean", "message": "No valid public IPs supplied for PTR sweep"}

    # Expand candidate set: for each unique discovered IP, check adjacent range (ip-3 to ip+3)
    expanded = set(valid_ips)
    for ip_str in list(valid_ips)[:20]:
        try:
            ip_int = int(ipaddress.ip_address(ip_str))
            for offset in (-2, -1, 1, 2):
                neighbor = str(ipaddress.ip_address(ip_int + offset))
                expanded.add(neighbor)
        except Exception:
            pass

    targets = sorted(list(expanded))[:max_ips]

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 2.5

    sem = asyncio.Semaphore(12)
    results: list[dict[str, Any]] = []
    classified: dict[str, list[str]] = {k: [] for k in INFRA_PATTERNS}

    async def check_ip(ip: str):
        async with sem:
            hostname = await _resolve_ptr(ip, resolver)
            if hostname:
                results.append({
                    "ip": ip,
                    "hostname": hostname,
                    "source": "ptr_sweep",
                })
                for cat, pattern in INFRA_PATTERNS.items():
                    if pattern.search(hostname):
                        classified[cat].append(f"{ip} -> {hostname}")

    await asyncio.gather(*(check_ip(ip) for ip in targets))

    # Remove empty categories
    classified = {k: v for k, v in classified.items() if v}

    status = {
        "status": "ok",
        "message": f"Resolved {len(results)} PTR record(s) across {len(targets)} queried IP(s)",
        "ips_queried": len(targets),
        "hostnames_found": len(results),
    }

    return results, classified, status
