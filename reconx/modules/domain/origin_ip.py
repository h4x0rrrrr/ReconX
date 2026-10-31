"""WAF & CDN Bypass / Origin IP Unmasking Engine.

Identifies potential origin backend server IPs bypassing Cloudflare,
Akamai, CloudFront, Fastly, and other CDNs through DNS correlation,
SSL certificate SAN matches on non-CDN IPs, and MX/mail infrastructure.
"""
from __future__ import annotations

import asyncio
from typing import Any

from reconx.utils.logger import debug, info

# Known CDN IPv4 ranges (prefixes) to distinguish CDN edge nodes from true origin servers
CDN_PROVIDERS = [
    ("Cloudflare", ["103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "141.101.", "162.158.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.", "173.245.", "188.114.", "190.93.", "197.234.", "198.41."]),
    ("Fastly", ["151.101.", "199.232.", "146.75."]),
    ("Akamai", ["23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.", "23.40.", "23.41.", "23.42.", "23.43.", "23.44.", "23.45.", "23.46.", "23.47.", "23.48.", "23.49.", "23.50.", "23.51.", "23.52.", "23.53.", "23.54.", "23.55.", "23.56.", "23.57.", "23.58.", "23.59.", "23.60.", "23.61.", "23.62.", "23.63.", "23.64.", "23.65.", "23.66.", "23.67.", "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.", "104.70.", "104.71.", "104.72.", "104.73.", "104.74.", "104.75.", "104.76.", "104.77.", "104.78.", "104.79.", "104.80.", "104.81.", "104.82.", "104.83.", "104.84.", "104.85.", "104.86.", "104.87.", "104.88.", "104.89.", "104.90.", "104.91.", "104.92.", "104.93.", "104.94.", "104.95."]),
    ("CloudFront", ["13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.", "13.227.", "13.249.", "18.64.", "18.65.", "18.66.", "18.67.", "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.", "54.240.", "64.252.", "65.8.", "65.9.", "99.84.", "99.86.", "143.204.", "204.246.", "205.251."]),
    ("Incapsula", ["199.83.", "149.126.", "103.28.", "185.11."]),
]

def is_cdn_ip(ip: str) -> str | None:
    """Return CDN name if IP is a known CDN edge node, else None."""
    for cdn_name, prefixes in CDN_PROVIDERS:
        if any(ip.startswith(pfx) for pfx in prefixes):
            return cdn_name
    return None

ORIGIN_SUBDOMAIN_PREFIXES = [
    "direct", "origin", "cpanel", "webmail", "mail", "dev", "stage",
    "staging", "internal", "admin", "vpn", "gateway", "backend",
    "autodiscover", "sip", "portal", "test", "legacy",
]

async def unmask_origin_ips(
    target: str,
    subdomains: list[dict[str, Any]],
    network_services: list[dict[str, Any]],
    live_hosts: list[dict[str, Any]],
    dns_records: dict[str, Any],
    client: Any = None,
) -> tuple[list[dict[str, Any]], str]:
    """Correlate passive intelligence to find non-CDN backend origin server IPs."""
    # 1. Determine if main target is fronted by a CDN
    target_cdn = None
    target_ips: list[str] = []

    # Check DNS A records of main target
    a_records = dns_records.get("A", []) if isinstance(dns_records, dict) else []
    for rec in a_records:
        val = rec.get("value", "") if isinstance(rec, dict) else str(rec)
        target_ips.append(val)
        cdn = is_cdn_ip(val)
        if cdn:
            target_cdn = cdn

    # Also check live hosts for CDN headers
    for h in live_hosts:
        headers = h.get("headers", {})
        if any("cf-ray" in k.lower() or "cloudflare" in str(v).lower() for k, v in headers.items()):
            target_cdn = "Cloudflare"
            break
        elif any("x-amz-cf-id" in k.lower() or "cloudfront" in str(v).lower() for k, v in headers.items()):
            target_cdn = "CloudFront"
            break
        elif any("fastly" in str(v).lower() for v in headers.values()):
            target_cdn = "Fastly"
            break

    candidates: dict[str, dict[str, Any]] = {}

    # 2. Check direct / origin subdomain resolutions
    sub_map = {s.get("host", "").lower(): s for s in subdomains if s.get("host")}
    for prefix in ORIGIN_SUBDOMAIN_PREFIXES:
        sub_name = f"{prefix}.{target.lower()}"
        if sub_name in sub_map:
            # Check resolved IP
            ip = sub_map[sub_name].get("ip") or sub_map[sub_name].get("resolved_ip")
            if not ip:
                try:
                    import socket
                    loop = asyncio.get_running_loop()
                    ip = await loop.run_in_executor(None, socket.gethostbyname, sub_name)
                except Exception:
                    ip = None
            if ip and not is_cdn_ip(ip) and not ip.startswith(("10.", "172.16.", "192.168.", "127.")):
                candidates[ip] = {
                    "ip": ip,
                    "target": target,
                    "matched_host": sub_name,
                    "fronted_by_cdn": target_cdn or "CDN/WAF",
                    "evidence": f"Direct DNS resolution on {sub_name} (non-CDN IP)",
                    "confidence": "High" if prefix in ("direct", "origin", "backend") else "Medium",
                    "source": "Subdomain Resolution",
                }

    # 3. Check Network Services (Censys / Shodan) for SSL Certificate SAN matches on non-CDN IPs
    for svc in network_services:
        ip = svc.get("ip", "")
        if not ip or is_cdn_ip(ip) or ip.startswith(("10.", "172.16.", "192.168.", "127.")):
            continue

        raw = svc.get("raw", {})
        cert_sans = raw.get("tls_sans", []) or svc.get("technologies", [])
        banner = str(svc.get("banner", "")).lower()

        # Check if target domain appears in certificate SAN or banner
        matched = False
        if any(target.lower() in str(san).lower() for san in cert_sans):
            matched = True
        elif target.lower() in banner:
            matched = True

        if matched:
            port = svc.get("port", 443)
            confidence = "High" if (port in (443, 8443) and any(target.lower() in str(s).lower() for s in cert_sans)) else "Medium"
            candidates[ip] = {
                "ip": ip,
                "port": port,
                "target": target,
                "matched_host": svc.get("host") or target,
                "fronted_by_cdn": target_cdn or "CDN/WAF",
                "evidence": f"Port {port} SSL certificate matches target domain on direct IP ({svc.get('source', 'Shodan/Censys')})",
                "confidence": confidence,
                "source": svc.get("source", "Network Intelligence"),
            }

    # 4. Check MX Mail Server IPs
    mx_records = dns_records.get("MX", []) if isinstance(dns_records, dict) else []
    for mx in mx_records:
        host = mx.get("host") or (mx.get("value", "").split()[-1] if isinstance(mx, dict) else str(mx))
        if host and target.lower() in host.lower():
            try:
                import socket
                loop = asyncio.get_running_loop()
                mx_ip = await loop.run_in_executor(None, socket.gethostbyname, host.strip("."))
                if mx_ip and not is_cdn_ip(mx_ip) and not mx_ip.startswith(("10.", "172.16.", "192.168.", "127.")):
                    if mx_ip not in candidates:
                        candidates[mx_ip] = {
                            "ip": mx_ip,
                            "target": target,
                            "matched_host": host,
                            "fronted_by_cdn": target_cdn or "CDN/WAF",
                            "evidence": f"Mail exchange (MX) server {host} resolves to same subnet/provider",
                            "confidence": "Low",
                            "source": "MX Infrastructure",
                        }
            except Exception:
                pass

    final_results = sorted(list(candidates.values()), key=lambda x: (x["confidence"] != "High", x["confidence"] != "Medium"))
    status = f"Completed ({len(final_results)} potential origin backend IP(s) discovered)"
    return final_results, status
