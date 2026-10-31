"""ASN and BGP CIDR prefix discovery module.

Discovers Autonomous System Numbers (ASNs), BGP routing prefixes,
and organizational netblocks using Team Cymru DNS and BGPView.
"""
from __future__ import annotations

import asyncio
import socket
from typing import Any

from reconx.utils.logger import debug, info, warn

async def lookup_asn_cymru(ip: str) -> dict[str, Any] | None:
    """Query Team Cymru IP-to-ASN DNS service (origin.asn.cymru.com).
    Benign, passive DNS TXT lookup.
    """
    try:
        # Only IPv4 for Cymru origin lookup
        octets = ip.strip().split(".")
        if len(octets) != 4:
            return None
        rev_ip = ".".join(reversed(octets))
        query_host = f"{rev_ip}.origin.asn.cymru.com"

        loop = asyncio.get_running_loop()
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        def _resolve():
            try:
                answers = resolver.resolve(query_host, "TXT")
                for rdata in answers:
                    txt = "".join(str(s.decode() if isinstance(s, bytes) else s) for s in rdata.strings).strip('"')
                    # format: ASN | CIDR | CC | Registry | Allocated
                    parts = [p.strip() for p in txt.split("|")]
                    if len(parts) >= 3:
                        asn = parts[0].split()[0] if parts[0] else ""
                        cidr = parts[1] if len(parts) > 1 else ""
                        cc = parts[2] if len(parts) > 2 else ""
                        return {
                            "ip": ip,
                            "asn": f"AS{asn}" if not asn.startswith("AS") else asn,
                            "cidr": cidr,
                            "country": cc,
                            "registry": parts[3] if len(parts) > 3 else "",
                            "source": "Team Cymru DNS",
                        }
            except Exception:
                return None
            return None

        return await loop.run_in_executor(None, _resolve)
    except Exception as exc:
        debug(f"Cymru ASN lookup error for {ip}: {exc}")
        return None

async def lookup_asn_bgpview(ip: str, client: Any = None) -> dict[str, Any] | None:
    """Enrich ASN details via BGPView public API."""
    try:
        url = f"https://api.bgpview.io/ip/{ip}"
        if client:
            resp = await client.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "ok":
                    ip_data = data.get("data", {})
                    ptr = ip_data.get("ptr_record", "")
                    prefixes = ip_data.get("prefixes", [])
                    rir = ip_data.get("rir_allocation", {})
                    asn_info = {}
                    if prefixes:
                        p0 = prefixes[0]
                        asn_node = p0.get("asn", {})
                        asn_info = {
                            "ip": ip,
                            "asn": f"AS{asn_node.get('asn', '')}",
                            "asn_name": asn_node.get("name", ""),
                            "description": asn_node.get("description", ""),
                            "cidr": p0.get("prefix", ""),
                            "country": asn_node.get("country_code", ""),
                            "rir": rir.get("rir_name", ""),
                            "source": "BGPView",
                        }
                        return asn_info
    except Exception as exc:
        debug(f"BGPView lookup error for {ip}: {exc}")
    return None

async def enumerate_asn_ranges(
    ips: list[str],
    client: Any = None,
    concurrency: int = 8,
) -> tuple[list[dict[str, Any]], str]:
    """Enumerate ASNs, CIDR blocks, and owner organizations for discovered IP addresses."""
    unique_ips = [ip for ip in dict.fromkeys(ips) if ip and not ip.startswith(("10.", "172.16.", "192.168.", "127."))]
    if not unique_ips:
        return [], "Skipped: No public IP addresses to resolve ASN blocks"

    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []

    async def _resolve_ip(ip: str):
        async with sem:
            # 1. Fast DNS query first
            res = await lookup_asn_cymru(ip)
            # 2. Enrich with BGPView if client available
            if client:
                bgp = await lookup_asn_bgpview(ip, client)
                if bgp:
                    if res:
                        res.update({k: v for k, v in bgp.items() if v})
                    else:
                        res = bgp
            if res:
                results.append(res)

    tasks = [_resolve_ip(ip) for ip in unique_ips[:30]]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate results by ASN + CIDR
    deduped: dict[str, dict[str, Any]] = {}
    for r in results:
        key = f"{r.get('asn')}_{r.get('cidr')}"
        if key not in deduped:
            deduped[key] = r
        else:
            # Aggregate IPs under this netblock
            existing = deduped[key]
            if "ips" not in existing:
                existing["ips"] = [existing.get("ip")]
            if r.get("ip") not in existing["ips"]:
                existing["ips"].append(r.get("ip"))

    final_list = list(deduped.values())
    status = f"Completed ({len(final_list)} unique ASN/CIDR block(s) identified)"
    return final_list, status
