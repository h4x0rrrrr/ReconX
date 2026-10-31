"""Concurrent passive-first domain recon, with explicitly opt-in bounded HTTP checks, WHOIS, PTR sweep, and document metadata."""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import subprocess
from urllib.parse import urlparse, urljoin
from typing import Any
import httpx
from reconx.core.config import load_config
from reconx.core.plugins import PluginContext, PluginManager, deduplicate, RateGate
from reconx.plugins import BUILTIN_PLUGINS
from reconx.core.report import Findings
from reconx.utils.logger import info, ok, warn
from reconx.utils.session import create_async_client
from reconx.modules.domain.vhosts import discover_vhosts
from reconx.modules.domain.ptr_sweep import sweep_reverse_dns
from reconx.modules.domain.doc_metadata import harvest_document_metadata
from reconx.modules.domain.vendor_correlation import extract_vendor_trackers
from reconx.modules.domain.email_security import audit_email_security
from reconx.modules.domain.gateway_fingerprint import fingerprint_gateways
from reconx.modules.domain.takeovers import audit_subdomain_takeovers
from reconx.modules.domain.cloud_buckets import audit_cloud_buckets
from reconx.modules.domain.security_headers import audit_security_headers
from reconx.modules.domain.technologies import detect_technologies, enrich_network_services
from reconx.modules.domain.asn_recon import enumerate_asn_ranges
from reconx.modules.domain.origin_ip import unmask_origin_ips
from reconx.modules.domain.vuln_intel import correlate_vulnerabilities
from reconx.modules.domain.ntlm_intel import check_ntlm_disclosures
from reconx.modules.domain.github_recon import enumerate_github_org

async def _active_probe(hosts: list[str], cfg: dict[str, Any]):
    sem = asyncio.Semaphore(max(1, min(8, cfg.get("concurrency", 6))))
    gates = {}
    probes = []
    tls = []
    pages_for_trackers = []

    async with create_async_client(cfg, timeout=cfg.get("request_timeout", 12.0)) as client:
        async def one(host: str):
            async with sem:
                for scheme in ("https://", "http://"):
                    try:
                        await gates.setdefault(host.casefold(), RateGate(cfg.get("rate_seconds", 0.25))).wait()
                        r = await client.get(scheme + host)
                        body = r.text[:500_000]
                        title_match = re.search(r"<title[^>]*>(.*?)</title", body, re.I | re.S)
                        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:160] if title_match else ""
                        techs = detect_technologies(
                            headers=dict(r.headers),
                            html=body,
                            title=title,
                            port=443 if scheme == "https://" else 80,
                        )
                        row = {
                            "host": host,
                            "url": str(r.url),
                            "status": r.status_code,
                            "title": title,
                            "server": r.headers.get("server", ""),
                            "technologies": techs,
                            "headers": dict(r.headers),
                            "source": "active_http_probe",
                        }
                        pages_for_trackers.append({"url": str(r.url), "body": body})

                        if scheme == "https://":
                            try:
                                import ssl, socket as _socket
                                def get_cert(h):
                                    context = ssl.create_default_context()
                                    with _socket.create_connection((h, 443), timeout=3) as sock:
                                        with context.wrap_socket(sock, server_hostname=h) as ss:
                                            return ss.getpeercert()
                                cert = await asyncio.to_thread(get_cert, host)
                                sans = [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"]
                                if sans:
                                    tls.append({"host": host, "sans": sans, "source": "tls_certificate"})
                            except Exception:
                                pass
                        return row
                    except Exception:
                        continue
                return None

        rows = await asyncio.gather(*(one(h) for h in hosts[:100]))
        probes = [x for x in rows if x]

    return probes, tls, pages_for_trackers

def _deep_subdomains(domain: str) -> list[dict[str, str]]:
    """Run installed passive subdomain tools concurrently; missing tools are simply skipped."""
    jobs = []
    if shutil.which("subfinder"):
        jobs.append(("subfinder", ["subfinder", "-d", domain, "-silent"], 150))
    amass_bin = "/usr/lib/amass/amass" if os.path.isfile("/usr/lib/amass/amass") else shutil.which("amass")
    if amass_bin and (amass_bin != "/usr/bin/amass" or os.path.exists("/usr/share/libpostal/transliteration")):
        jobs.append(("amass", [amass_bin, "enum", "-passive", "-d", domain, "-silent"], 180))
    def execute(job):
        name, cmd, timeout = job
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return [{"host": x.strip().lower(), "source": name, "evidence": "passive subdomain enumeration"} for x in p.stdout.splitlines() if x.strip()]
        except Exception:
            return []
    if not jobs:
        return []
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        results = list(pool.map(execute, jobs))
    return [item for group in results for item in group]

def run_domain_recon(
    domain: str,
    active: bool = False,
    deep: bool = False,
    vhosts: bool = False,
    vhost_wordlist: str | None = None,
    ptr_sweep: bool = False,
    takeovers: bool = False,
    buckets: bool = False,
    security_headers: bool = False,
) -> Findings:
    domain = domain.strip().lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("Enter a valid domain name, e.g. example.com (not a URL).")
    cfg = load_config()
    findings = Findings(target=domain, mode="domain")
    info(f"=== DOMAIN RECON: {domain} ===")

    from .certificates import enumerate_certificates

    async def collect():
        async with create_async_client(cfg, timeout=cfg.get("request_timeout", 12.0)) as client:
            ctx = PluginContext(client, cfg, domain, "domain", {})
            manager = PluginManager([p for p in BUILTIN_PLUGINS if "domain" in p.modes], cfg.get("concurrency", 8))
            p_task = manager.run(ctx)
            c_task = enumerate_certificates(domain, client, cfg)
            p_res, (live_c, all_c, ct_s, c_stat) = await asyncio.gather(p_task, c_task)
            return p_res, live_c, all_c, ct_s, c_stat

    plugin_results, live_cert, all_certs, ct_subs, cert_status = asyncio.run(collect())
    source_status = []
    source_status.append({
        "source": "certificates",
        "status": cert_status.get("status", "ok"),
        "message": f"Live cert: {cert_status.get('live_cert_found', False)}, {cert_status.get('total_certs_enumerated', 0)} CT records",
        "items_returned": len(all_certs),
    })
    findings_github = []
    all_subs = [{"host": domain, "source": "input", "evidence": "user-supplied root domain"}]
    all_subs.extend(ct_subs)
    historical = []
    dns_records: dict[str, list[dict[str, str]]] = {}
    asn = []
    whois_record = {}
    m365_record = {}
    network_services = []
    urlscan_records = []

    for pr in plugin_results:
        source_status.append({"source": pr.source, "status": pr.status, "message": pr.message, "items_returned": len(pr.items)})
        if pr.source == "crtsh":
            all_subs.extend(pr.items)
        elif pr.source == "wayback":
            historical.extend(pr.items)
        elif pr.source == "dns":
            for item in pr.items:
                dns_records.setdefault(item["record_type"], []).append({"value": item["value"], "source": pr.source})
        elif pr.source == "bgpview":
            asn.extend(pr.items)
        elif pr.source == "whois":
            if pr.items:
                whois_record = pr.items[0]
        elif pr.source == "m365":
            if pr.items:
                m365_record = pr.items[0]
        elif pr.source == "github_code":
            findings_github = pr.items
        elif pr.source in ("shodan", "censys"):
            network_services.extend(pr.items)
        elif pr.source == "urlscan":
            urlscan_records.extend(pr.items)

    if deep:
        all_subs.extend(_deep_subdomains(domain))

    all_subs = deduplicate([x for x in all_subs if x.get("host") and (x["host"] == domain or x["host"].endswith("." + domain))], key_fields=("host",))
    historical = deduplicate(historical, key_fields=("url",))

    findings.add("subdomains", sorted(all_subs, key=lambda x: x["host"]))
    findings.add("dns_records", dns_records)
    findings.add("asn_intelligence", deduplicate(asn, key_fields=("prefix",)))
    findings.add("historical_urls", historical)
    findings.add("interesting_historical_urls", [x for x in historical if x.get("interesting")])
    findings.add("live_certificate", live_cert)
    findings.add("certificates", all_certs)
    network_services = deduplicate(network_services, key_fields=("ip", "port", "source"))
    if network_services:
        async def _enrich_svcs():
            async with create_async_client(cfg, timeout=cfg.get("request_timeout", 8.0)) as c:
                return await enrich_network_services(network_services, c, cfg)
        network_services = asyncio.run(_enrich_svcs())
    findings.add("network_services", network_services)
    findings.add("urlscan_records", urlscan_records)
    findings.add("source_status", source_status)
    findings.add("whois", whois_record)
    findings.add("m365_identity", m365_record)
    findings.add("email_security", audit_email_security(domain, dns_records))
    findings.add("github_code_references", findings_github)

    cloud_re = re.compile(r"https?://[^/\s]*(?:s3[.-][a-z0-9-]+\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^\s]*", re.I)
    findings.add("cloud_references", deduplicate([{"url": u, "source": "historical_url_pattern"} for row in historical for u in cloud_re.findall(row.get("url", ""))], key_fields=("url",)))

    # Collect discovered IPs for PTR sweep if requested
    discovered_ips = [item.get("value") for item in dns_records.get("A", []) if item.get("value")]
    discovered_ips.extend([item.get("ip") for item in asn if item.get("ip")])
    discovered_ips.extend([item.get("ip") for item in network_services if item.get("ip")])
    discovered_ips = list(dict.fromkeys(discovered_ips))

    if ptr_sweep or active:
        if discovered_ips:
            ptr_records, infra_cat, ptr_status = asyncio.run(sweep_reverse_dns(discovered_ips, cfg))
            findings.add("ptr_records", ptr_records)
            findings.add("infrastructure_categories", infra_cat)
            source_status.append({"source": "ptr_sweep", "status": ptr_status.get("status", "ok"), "message": ptr_status.get("message", ""), "items_returned": len(ptr_records)})

    # Document metadata harvesting from historical URLs
    hist_urls = [h.get("url", "") for h in historical]
    doc_meta, conventions, doc_status = asyncio.run(harvest_document_metadata(domain, hist_urls, cfg))
    if doc_meta:
        findings.add("document_metadata", doc_meta)
        findings.add("username_conventions", conventions)
        source_status.append({"source": "document_metadata", "status": doc_status.get("status", "ok"), "message": doc_status.get("message", ""), "items_returned": len(doc_meta)})

    # Identify passive API and script endpoints from historical URLs
    api_re = re.compile(r"https?://[^/\s]+/(?:api|v[0-9]+|rest|graphql|wp-json|oauth|auth|wp-admin/admin-ajax)[/\S]*", re.I)
    passive_endpoints = [
        {"url": u, "js_source": "historical_archive", "source": "historical_api_endpoint"}
        for u in (h.get("url", "") for h in historical)
        if api_re.search(u)
    ]
    findings.add("js_endpoints", deduplicate(passive_endpoints, key_fields=("url",)))

    probes: list[dict[str, Any]] = []
    if active:
        hosts = [x["host"] for x in all_subs]
        probes, tls, tracker_pages = asyncio.run(_active_probe(hosts, cfg))
        findings.add("live_hosts", probes)
        findings.add("tls_sans", tls)

        # Extract analytics & vendor tracking codes
        if tracker_pages:
            trackers, grouped_trackers, tracker_status = extract_vendor_trackers(tracker_pages)
            findings.add("vendor_trackers", trackers)
            findings.add("tracker_relationships", grouped_trackers)

        from .enrichment import enrich_hosts
        enrichment = asyncio.run(enrich_hosts(probes, cfg))
        for k, v in enrichment.items():
            if k in ("cloud_references", "js_endpoints"):
                v = deduplicate((findings.data.get(k, []) or []) + v, key_fields=("url",))
            findings.add(k, v)

        # Fingerprint enterprise perimeter gateways and remote access portals
        async def _check_gateways(p_list):
            async with create_async_client(cfg, timeout=cfg.get("request_timeout", 8.0)) as c:
                return await fingerprint_gateways(p_list, c, cfg)

        gateways, gateway_status = asyncio.run(_check_gateways(probes))
        if gateways:
            findings.add("perimeter_gateways", gateways)
            source_status.append({
                "source": "gateway_fingerprint",
                "status": gateway_status.get("status", "ok"),
                "message": gateway_status.get("message", ""),
                "items_returned": len(gateways),
            })
    else:
        findings.add("active_checks", "skipped (use --active to perform bounded HTTP/TLS checks)")

    if vhosts:
        info("Checking virtual host candidates against baseline response...")
        vhost_results, vhost_status = asyncio.run(discover_vhosts(domain, cfg, wordlist=vhost_wordlist))
        findings.add("vhosts", vhost_results)
        source_status.append({
            "source": "vhosts",
            "status": vhost_status.get("status", "ok"),
            "message": vhost_status.get("message", ""),
            "items_returned": len(vhost_results),
        })

    if takeovers:
        info("Auditing subdomains for dangling CNAME pointers & takeover risks...")
        async def _check_takeovers():
            async with create_async_client(cfg, timeout=cfg.get("request_timeout", 8.0)) as c:
                return await audit_subdomain_takeovers([x["host"] for x in all_subs], c, cfg)
        takeover_results, takeover_status = asyncio.run(_check_takeovers())
        findings.add("takeovers", takeover_results)
        source_status.append({
            "source": "takeovers",
            "status": takeover_status.get("status", "ok"),
            "message": takeover_status.get("message", ""),
            "items_returned": len(takeover_results),
        })

    if buckets:
        info("Auditing cloud storage bucket permutations (AWS S3, Azure Blob, GCP)...")
        sub_hosts = [x.get("host", "") for x in all_subs if x.get("host")]
        passive_cloud_urls = [r.get("url", "") for r in findings.data.get("cloud_references", []) if r.get("url")]
        from .cloud_buckets import extract_bucket_names_from_urls
        extra_bucket_names = extract_bucket_names_from_urls(passive_cloud_urls)

        async def _check_buckets():
            async with create_async_client(cfg, timeout=cfg.get("request_timeout", 6.0)) as c:
                return await audit_cloud_buckets(
                    domain,
                    c,
                    cfg,
                    discovered_subdomains=sub_hosts,
                    extra_names=extra_bucket_names,
                )
        bucket_results, bucket_status = asyncio.run(_check_buckets())
        findings.add("cloud_buckets", bucket_results)
        source_status.append({
            "source": "cloud_buckets",
            "status": bucket_status.get("status", "ok"),
            "message": bucket_status.get("message", ""),
            "items_returned": len(bucket_results),
        })
        if bucket_results:
            ok(f"Cloud buckets: Discovered {len(bucket_results)} exposed/protected bucket(s)")
        else:
            info(f"Cloud buckets: {bucket_status.get('message', 'No exposed buckets found')}")

    if security_headers:
        info("Auditing HTTP security headers...")
        sec_header_results = []
        target_probes = probes if active else []
        if not target_probes:
            async def _probe_apex():
                async with create_async_client(cfg, timeout=cfg.get("request_timeout", 8.0)) as c:
                    for scheme in ("https://", "http://"):
                        try:
                            r = await c.get(f"{scheme}{domain}")
                            return [{
                                "host": domain,
                                "url": str(r.url),
                                "headers": dict(r.headers),
                            }]
                        except Exception:
                            continue
                return []
            target_probes = asyncio.run(_probe_apex())

        for p in target_probes:
            hdrs = p.get("headers", {})
            if hdrs:
                audit = audit_security_headers(hdrs)
                sec_header_results.append({
                    "host": p.get("host", ""),
                    "url": p.get("url", ""),
                    "grade": audit["grade"],
                    "score": audit["score"],
                    "missing": audit["missing_headers"],
                    "present": list(audit["present_headers"].keys()),
                })
        findings.add("security_headers", sec_header_results)
        source_status.append({
            "source": "security_headers",
            "status": "ok",
            "message": f"Audited {len(sec_header_results)} host(s)",
            "items_returned": len(sec_header_results),
        })

    # Aggregate discovered technologies across network services and live hosts
    all_techs = []
    for s in network_services:
        all_techs.extend(s.get("technologies", []))
    for p in findings.data.get("live_hosts", []):
        all_techs.extend(p.get("technologies", []))
    unique_techs = list(dict.fromkeys(all_techs))
    findings.add("technologies", unique_techs)

    # 1. Correlate identified technologies against CVE & CISA KEV catalogs
    vulns, vuln_msg = correlate_vulnerabilities(unique_techs, network_services, probes)
    findings.add("vulnerabilities", vulns)
    source_status.append({
        "source": "vuln_intel",
        "status": "ok",
        "message": vuln_msg,
        "items_returned": len(vulns),
    })

    # 2. Extract public IPs for ASN & BGP CIDR block resolution
    discovered_ips = []
    for r in dns_records.get("A", []):
        discovered_ips.append(r.get("value", "") if isinstance(r, dict) else str(r))
    for s in network_services:
        if s.get("ip"):
            discovered_ips.append(s.get("ip"))

    async def _async_extra_domain_tasks():
        async with create_async_client(cfg, timeout=cfg.get("request_timeout", 8.0)) as c:
            # ASN / BGP routing netblocks
            asn_list, _ = await enumerate_asn_ranges(discovered_ips, client=c)
            # WAF & CDN Bypass / Origin IP Discovery
            origins, _ = await unmask_origin_ips(domain, all_subs, network_services, probes, dns_records, client=c)
            # Passive GitHub Organization OSINT
            gh_data, _ = await enumerate_github_org(domain, client=c)
            # NTLM Internal Identity challenge extraction
            ntlm_data = []
            if active and probes:
                ntlm_data, _ = await check_ntlm_disclosures(probes, client=c)
            return asn_list, origins, gh_data, ntlm_data

    asn_res, origin_res, gh_res, ntlm_res = asyncio.run(_async_extra_domain_tasks())
    findings.add("asn_ranges", asn_res)
    findings.add("origin_ips", origin_res)
    findings.add("github_intel", gh_res)
    findings.add("ntlm_disclosure", ntlm_res)

    findings.auto_flag_domain()
    ok(f"Domain recon complete: {len(all_subs)} subdomains, {len(historical)} historical URLs")
    return findings
