"""Internal Identity & Active Directory NTLM Challenge Parser.

Extracts internal domain names, NetBIOS hostnames, Active Directory forest names,
and Windows OS build numbers via unauthenticated NTLM Type-2 challenges over HTTP/HTTPS.
"""
from __future__ import annotations

import base64
import struct
from typing import Any

from reconx.utils.logger import debug

# Standard Benign NTLM Type-1 Negotiate Message
# Flags: Negotiate Unicode, Negotiate OEM, Request Target, Negotiate NTLM, Negotiate Always Sign, Negotiate Extended Security, Negotiate Target Info, Negotiate 128
NTLM_TYPE1_HEADER = "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAFAs4OAAAADw=="

def parse_ntlm_type2_challenge(challenge_b64: str) -> dict[str, Any] | None:
    """Decode and parse an NTLM Type-2 challenge message into identity fields."""
    try:
        raw = base64.b64decode(challenge_b64)
        if len(raw) < 40 or not raw.startswith(b"NTLMSSP\x00\x02\x00\x00\x00"):
            return None

        # Target Info offset and length (offsets 40-48 in Type-2 message)
        target_info_len, _, target_info_offset = struct.unpack("<HHI", raw[40:48])
        os_version = ""
        if len(raw) >= 56:
            major, minor, build = struct.unpack("<BBH", raw[48:52])
            os_version = f"Windows {major}.{minor} (Build {build})"

        info_bytes = raw[target_info_offset : target_info_offset + target_info_len]
        idx = 0
        av_pairs: dict[str, str] = {}

        # AV ID mappings:
        # 0x0001: MsvAvNbComputerName
        # 0x0002: MsvAvNbDomainName
        # 0x0003: MsvAvDnsComputerName
        # 0x0004: MsvAvDnsDomainName
        # 0x0005: MsvAvDnsTreeName
        # 0x0007: MsvAvTimestamp
        id_names = {
            1: "netbios_computer_name",
            2: "netbios_domain_name",
            3: "dns_computer_name",
            4: "dns_domain_name",
            5: "dns_tree_name",
        }

        while idx + 4 <= len(info_bytes):
            av_id, av_len = struct.unpack("<HH", info_bytes[idx : idx + 4])
            if av_id == 0:  # MsvAvEOL
                break
            val_bytes = info_bytes[idx + 4 : idx + 4 + av_len]
            if av_id in id_names:
                try:
                    val_str = val_bytes.decode("utf-16le")
                    av_pairs[id_names[av_id]] = val_str
                except Exception:
                    pass
            idx += 4 + av_len

        if av_pairs:
            if os_version:
                av_pairs["os_version"] = os_version
            return av_pairs
    except Exception as exc:
        debug(f"NTLM challenge parsing failed: {exc}")
    return None

async def probe_ntlm_challenge(url: str, client: Any) -> dict[str, Any] | None:
    """Send NTLM Type-1 probe to URL and inspect WWW-Authenticate response header."""
    try:
        headers = {"Authorization": NTLM_TYPE1_HEADER}
        resp = await client.get(url, headers=headers, timeout=5.0)
        auth_hdr = resp.headers.get("www-authenticate", "")
        if "NTLM" in auth_hdr:
            parts = auth_hdr.split()
            for i, p in enumerate(parts):
                if p.lower() == "ntlm" and i + 1 < len(parts):
                    chal = parts[i + 1].strip(",")
                    parsed = parse_ntlm_type2_challenge(chal)
                    if parsed:
                        parsed["url"] = url
                        parsed["status_code"] = resp.status_code
                        return parsed
    except Exception as exc:
        debug(f"NTLM probe error for {url}: {exc}")
    return None

async def check_ntlm_disclosures(
    live_hosts: list[dict[str, Any]],
    client: Any,
    concurrency: int = 4,
) -> tuple[list[dict[str, Any]], str]:
    """Scan candidate web endpoints for NTLM challenge identity disclosures."""
    if not live_hosts or not client:
        return [], "Skipped: No live hosts or client"

    # Identify IIS or Windows-flavored hosts
    candidate_urls: list[str] = []
    for h in live_hosts:
        server = (h.get("server") or "").lower()
        title = (h.get("title") or "").lower()
        url = h.get("url", "")
        if any(kw in server + " " + title for kw in ("iis", "microsoft", "exchange", "owa", "autodiscover", "adfs", "rdweb", "sharepoint")):
            candidate_urls.append(url)
            # Also test common NTLM authentication endpoints
            base = url.rstrip("/")
            for ep in ("/owa/", "/autodiscover/autodiscover.xml", "/ews/", "/rpc/"):
                candidate_urls.append(f"{base}{ep}")

    if not candidate_urls:
        return [], "Skipped: No Microsoft/IIS services detected on live hosts"

    candidate_urls = list(dict.fromkeys(candidate_urls))[:15]
    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []

    async def _probe(u: str):
        async with sem:
            res = await probe_ntlm_challenge(u, client)
            if res:
                results.append(res)

    await asyncio.gather(*[_probe(u) for u in candidate_urls], return_exceptions=True)
    status = f"Completed ({len(results)} NTLM internal identity disclosure(s) extracted)"
    return results, status
