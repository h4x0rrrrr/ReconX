"""Comprehensive TLS / SSL Certificate & Certificate Transparency (CT) Intelligence."""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import socket
import ssl
from typing import Any
from urllib.parse import quote

import httpx
from reconx.core.cache import get_cache
from reconx.core.plugins import deduplicate
from reconx.utils.logger import ok, info, warn

def _parse_cert_date(date_str: str) -> datetime.datetime | None:
    if not date_str:
        return None
    for fmt in (
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.datetime.strptime(date_str.strip(), fmt).replace(tzinfo=datetime.timezone.utc)
        except Exception:
            continue
    return None

def fetch_live_certificate(domain: str, port: int = 443, timeout: float = 6.0) -> dict[str, Any] | None:
    """Perform a direct TLS handshake on the target domain/port to extract the active certificate."""
    try:
        cert: dict[str, Any] = {}
        der: bytes | None = None
        verify_error: str | None = None

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ss:
                    cert = ss.getpeercert() or {}
                    der = ss.getpeercert(binary_form=True)
        except (ssl.SSLCertVerificationError, ssl.SSLError) as ssl_err:
            verify_error = str(ssl_err)
            context = ssl._create_unverified_context()
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ss:
                    der = ss.getpeercert(binary_form=True)

        if not cert and not der:
            return None

        sha256 = hashlib.sha256(der).hexdigest() if der else ""
        
        # Extract Subject fields
        subject_dict = {}
        for rdn in cert.get("subject", ()):
            for k, v in rdn:
                subject_dict[k] = v
        common_name = subject_dict.get("commonName", domain)

        # Extract Issuer fields
        issuer_dict = {}
        for rdn in cert.get("issuer", ()):
            for k, v in rdn:
                issuer_dict[k] = v
        issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or ("Untrusted / Self-Signed" if verify_error else "Unknown Issuer")
        issuer_cn = issuer_dict.get("commonName") or ""

        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        not_before_dt = _parse_cert_date(not_before_str)
        not_after_dt = _parse_cert_date(not_after_str)

        now = datetime.datetime.now(datetime.timezone.utc)
        days_remaining = (not_after_dt - now).days if not_after_dt else 0
        is_expired = days_remaining < 0 if not_after_dt else False
        is_expiring_soon = 0 <= days_remaining <= 30 if not_after_dt else False

        if is_expired:
            status = "expired"
        elif is_expiring_soon:
            status = "expiring_soon"
        else:
            status = "valid"

        sans = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
        if common_name and common_name not in sans:
            sans.insert(0, common_name)

        return {
            "domain": domain,
            "port": port,
            "common_name": common_name,
            "subject": subject_dict,
            "issuer": f"{issuer_org} ({issuer_cn})" if issuer_cn and issuer_cn != issuer_org else issuer_org,
            "issuer_details": issuer_dict,
            "valid_from": not_before_dt.isoformat() if not_before_dt else not_before_str,
            "valid_to": not_after_dt.isoformat() if not_after_dt else not_after_str,
            "days_remaining": days_remaining,
            "status": status,
            "sans": sans,
            "serial_number": cert.get("serialNumber", ""),
            "sha256_fingerprint": sha256,
            "version": cert.get("version", 3),
            "ocsp": list(cert.get("OCSP", ())),
            "crl": list(cert.get("crlDistributionPoints", ())),
            "source": "live_tls_handshake",
            "evidence": f"Direct TLS handshake on {domain}:{port}",
        }
    except Exception as exc:
        return None

async def query_certspotter(domain: str, client: httpx.AsyncClient, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Query Certspotter API for certificate transparency records."""
    cache = get_cache(enabled=cfg.get("cache_enabled", True))
    cached = cache.get("certspotter", domain)
    if cached is not None:
        return cached

    url = f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains=true&expand=dns_names"
    try:
        r = await client.get(url, timeout=cfg.get("request_timeout", 10.0))
        if r.status_code != 200:
            return []
        items = []
        for x in r.json()[:60]:
            dns_names = [d.strip().lower().lstrip("*.").rstrip(".") for d in x.get("dns_names", []) if d]
            items.append({
                "id": str(x.get("id", "")),
                "common_name": dns_names[0] if dns_names else domain,
                "issuer": (x.get("issuer") or {}).get("name", "Certificate Authority"),
                "valid_from": x.get("not_before", ""),
                "valid_to": x.get("not_after", ""),
                "sans": dns_names,
                "sha256_fingerprint": x.get("cert_sha256", ""),
                "source": "certspotter",
                "evidence": "Certspotter Certificate Transparency Monitor",
            })
        cache.set("certspotter", domain, items, ttl=cfg.get("cache_ttl", 86400))
        return items
    except Exception:
        return []

async def query_crtsh_certificates(domain: str, client: httpx.AsyncClient, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Query CRT.sh for certificate transparency records."""
    cache = get_cache(enabled=cfg.get("cache_enabled", True))
    cached = cache.get("crtsh_certs", domain)
    if cached is not None:
        return cached

    url = f"https://crt.sh/?q={quote(domain)}&output=json"
    try:
        r = await client.get(url, timeout=cfg.get("request_timeout", 10.0))
        if r.status_code != 200:
            return []
        items = []
        for x in r.json()[:60]:
            matching = [h.strip().lower().lstrip("*.").rstrip(".") for h in (x.get("name_value") or "").splitlines() if h]
            items.append({
                "id": str(x.get("id", "")),
                "common_name": x.get("common_name") or (matching[0] if matching else domain),
                "issuer": x.get("issuer_name", ""),
                "valid_from": x.get("not_before", ""),
                "valid_to": x.get("not_after", ""),
                "sans": matching,
                "serial_number": str(x.get("serial_number", "")),
                "source": "crtsh",
                "evidence": "CRT.sh Certificate Transparency Database",
            })
        cache.set("crtsh_certs", domain, items, ttl=cfg.get("cache_ttl", 86400))
        return items
    except Exception:
        return []

async def enumerate_certificates(
    domain: str,
    client: httpx.AsyncClient,
    cfg: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    """Enumerate live TLS certificate, Certificate Transparency records, and discovered subdomains."""
    info("Enumerating SSL/TLS certificates and Certificate Transparency (CT) records...")

    # 1. Live TLS Handshake (run in thread pool to avoid blocking async loop)
    live_cert = await asyncio.to_thread(fetch_live_certificate, domain, 443, 6.0)

    # 2. Query CT Providers concurrently
    ct_tasks = [
        query_certspotter(domain, client, cfg),
        query_crtsh_certificates(domain, client, cfg),
    ]
    ct_results = await asyncio.gather(*ct_tasks, return_exceptions=True)
    
    all_certs: list[dict[str, Any]] = []
    if live_cert:
        all_certs.append(live_cert)

    discovered_subdomains: list[dict[str, str]] = []

    for res in ct_results:
        if isinstance(res, list):
            all_certs.extend(res)
            for cert in res:
                for san in cert.get("sans", []):
                    if san == domain or san.endswith("." + domain):
                        discovered_subdomains.append({
                            "host": san,
                            "source": cert.get("source", "certificate_transparency"),
                            "evidence": f"Certificate Transparency SAN ({cert.get('source')})",
                        })

    if live_cert:
        for san in live_cert.get("sans", []):
            if san == domain or san.endswith("." + domain):
                discovered_subdomains.append({
                    "host": san,
                    "source": "tls_certificate",
                    "evidence": "Live TLS Subject Alternative Name (SAN)",
                })

    dedup_certs = deduplicate(all_certs, key_fields=("sha256_fingerprint", "serial_number", "id", "common_name"))
    dedup_subs = deduplicate(discovered_subdomains, key_fields=("host",))

    status = {
        "status": "ok" if (live_cert or dedup_certs) else "unavailable",
        "live_cert_found": live_cert is not None,
        "total_certs_enumerated": len(dedup_certs),
        "ct_subdomains_extracted": len(dedup_subs),
    }

    if live_cert:
        ok(f"Live TLS Certificate: {live_cert.get('issuer')} (Expires: {live_cert.get('valid_to', '')[:10]}, {live_cert.get('days_remaining')} days remaining, {len(live_cert.get('sans', []))} SANs)")
    else:
        info(f"Target port 443 did not return a live TLS certificate; CT logs yielded {len(dedup_certs)} historical records.")

    return live_cert, dedup_certs, dedup_subs, status
