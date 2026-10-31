"""ReconX 0.3.3 — concurrent, plugin-based passive-first OSINT CLI."""
from __future__ import annotations
import argparse
import asyncio
import os
import re
from datetime import datetime
from reconx.core.config import load_config
from reconx.core.installer import print_status_report
from reconx.core.report import Findings
from reconx.utils.logger import info, ok, warn

def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", text.strip()).strip("_").lower()[:70] or "target"

def _make_out_dir(mode: str, target: str) -> str:
    path = os.path.join("recon_output", f"{mode}_{_slug(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(path, exist_ok=True)
    return path

def _print_executive_conclusion(findings: Findings, out_dir: str, m_path: str, j_path: str, csvs: list[str], h_path: str = "") -> None:
    data = findings.data
    mode = findings.mode

    print("\n" + "=" * 76)
    print("#### Key Findings & Intelligence Discovered:")
    print("=" * 76)

    if mode == "domain":
        # 1. WHOIS / Registration
        whois = data.get("whois", {})
        if whois and isinstance(whois, dict) and whois.get("registrar"):
            created = str(whois.get("created_date", "N/A"))[:10]
            expires = str(whois.get("expiration_date", "N/A"))[:10]
            commitment = ""
            try:
                cy, ey = int(created[:4]), int(expires[:4])
                if ey > cy:
                    commitment = f" ({ey - cy}-year commitment)"
            except Exception:
                pass
            ns_str = ", ".join(whois.get("nameservers", [])) or "None"
            print(f"\n  • Domain Registration & Lifecycle (whois.json):")
            print(f"      • Registrar: {whois.get('registrar')}")
            print(f"      • Created: {created} · Expires: {expires}{commitment}")
            print(f"      • Name Servers: {ns_str} ({'DNSSEC Signed' if whois.get('dnssec') else 'Cloudflare / Unsigned'})")

        # 2. High-Risk Historical Artifacts
        interesting = data.get("interesting_historical_urls", [])
        if interesting and isinstance(interesting, list):
            print(f"\n  • High-Risk Historical Artifacts (interesting_historical_urls.txt):")
            for item in interesting[:5]:
                u = item.get("url", "") if isinstance(item, dict) else str(item)
                print(f"      • {u} — historical backup/config/env pattern archived in Wayback.")
            if len(interesting) > 5:
                print(f"      • ... and {len(interesting) - 5} more; see interesting_historical_urls.txt")

        # 3. JavaScript & API Endpoints
        js_eps = data.get("js_endpoints", [])
        if js_eps and isinstance(js_eps, list):
            sample_endpoints = [ep.get("url", "") for ep in js_eps if any(kw in ep.get("url", "").lower() for kw in ("widget", "api", "analytics", "admin", "graphql", "track"))][:3]
            sample_str = f", including {', '.join(sample_endpoints)}" if sample_endpoints else ""
            print(f"\n  • JavaScript & API Endpoints (js_endpoints.txt / js_endpoints.csv):")
            print(f"      • {len(js_eps)} unique endpoints extracted from live scripts and archives{sample_str}.")

        # 4. Corporate Identity & Document Intelligence
        conventions = data.get("username_conventions", [])
        docs = data.get("document_metadata", [])
        if conventions or docs:
            print(f"\n  • Corporate Identity & Document Intelligence (documents.csv):")
            if conventions:
                print(f"      • Inferred Username Conventions: {', '.join(conventions[:3])}")
            if docs:
                authors = list(dict.fromkeys(d.get("author") or d.get("creator") for d in docs if d.get("author") or d.get("creator")))
                if authors:
                    print(f"      • Extracted Document Authors: {', '.join(authors[:5])}")

        # 5. Active Attack Surface
        subs = data.get("subdomains", [])
        live = data.get("live_hosts", [])
        sans = data.get("tls_sans", [])
        metadata = data.get("public_metadata", [])
        favicons = data.get("favicon_hashes", [])
        vhosts = data.get("vhosts", [])
        ptrs = data.get("ptr_records", [])

        if subs or live or sans or vhosts or ptrs:
            print(f"\n  • Active Attack Surface & Infrastructure:")
            if subs:
                print(f"      • {len(subs)} Subdomains discovered (CRT.sh + Subfinder passive enumeration).")
            if live:
                print(f"      • {len(live)} Live Hosts confirmed active over HTTP/HTTPS.")
            if sans:
                print(f"      • {len(sans)} TLS SAN entries mapped across live SSL certificates.")
            if metadata:
                print(f"      • {len(metadata)} Public Metadata endpoints (OIDC, robots.txt, security metadata).")
            if favicons:
                print(f"      • {len(favicons)} Favicon mmh3 hashes collected.")
            if vhosts:
                print(f"      • {len(vhosts)} Virtual-host candidates fingerprinted via Host-header comparison.")
            if ptrs:
                print(f"      • {len(ptrs)} Reverse DNS (PTR) hostnames mapped.")

        # 6. Cloud Identity & Microsoft 365
        m365 = data.get("m365_identity", {})
        if m365 and isinstance(m365, dict) and m365.get("is_m365"):
            arch = "Hybrid On-Premises ADFS / STS" if m365.get("is_federated") else "Pure Managed Cloud (Azure AD Native)"
            tenant = m365.get("tenant_id") or "Undisclosed"
            print(f"\n  • Cloud Identity Architecture (m365.json):")
            print(f"      • Microsoft 365 / Entra ID Organization: Active")
            print(f"      • Azure Tenant GUID: {tenant}")
            print(f"      • Identity Architecture: {arch} (Namespace: {m365.get('namespace_type', 'Unknown')})")
            if m365.get("federation_brand"):
                print(f"      • Federation STS Brand: {m365.get('federation_brand')}")
            if m365.get("federation_auth_url"):
                print(f"      • Federation Auth URL: {m365.get('federation_auth_url')}")

        # 7. Inbound Email Security & DMARC
        email_sec = data.get("email_security", {})
        if email_sec and isinstance(email_sec, dict) and email_sec.get("seg_vendor"):
            dmarc = email_sec.get("dmarc", {})
            print(f"\n  • Inbound Email Security & Anti-Spoofing (email_security.json):")
            print(f"      • Email Security Gateway (SEG): {email_sec.get('seg_vendor')}")
            print(f"      • DMARC Anti-Spoofing Policy: {dmarc.get('policy', 'missing')} ({dmarc.get('compliance', 'N/A')})")
            print(f"      • Domain Spoofing Risk: {dmarc.get('spoofing_risk', 'Unknown').upper()}")

        # 8. Network Services & Open Ports
        services = data.get("network_services", [])
        if services and isinstance(services, list):
            print(f"\n  • Discovered Network Services & Open Ports (services.csv):")
            print(f"      • {len(services)} network service(s) / port(s) identified via Shodan & Censys:")
            for s in services[:10]:
                svc_desc = s.get("service") or s.get("product") or "unknown"
                org_desc = f" ({s.get('org')})" if s.get("org") else ""
                tech_desc = f" · Tech: {', '.join(s.get('technologies', []))}" if s.get("technologies") else ""
                print(f"      • [{s.get('source', 'port')}] {s.get('ip')}:{s.get('port')} — {svc_desc}{org_desc}{tech_desc}")
            if len(services) > 10:
                print(f"      • ... and {len(services) - 10} more open services (see services.csv & services.txt).")

        # 8b. Technology Stack & Frameworks
        techs = data.get("technologies", [])
        if techs and isinstance(techs, list):
            print(f"\n  • Identified Technology Stack & Web Frameworks:")
            print(f"      • {', '.join(techs[:15])}")

        # 9. TLS / SSL Certificates & CT Intelligence
        live_cert = data.get("live_certificate")
        certs = data.get("certificates", [])
        if live_cert or certs:
            print(f"\n  • TLS / SSL Certificates & Security Posture (certificates.csv):")
            if live_cert:
                status_desc = "[VALID]" if live_cert.get("status") == "valid" else f"[{live_cert.get('status', '').upper()}]"
                print(f"      • Subject Common Name : {live_cert.get('common_name')}")
                print(f"      • Certificate Issuer  : {live_cert.get('issuer')}")
                print(f"      • Validity Period     : {live_cert.get('valid_from', '')[:10]} to {live_cert.get('valid_to', '')[:10]} ({live_cert.get('days_remaining')} days remaining · {status_desc})")
                print(f"      • Alt Names (SANs)    : {len(live_cert.get('sans', []))} domains covered")
                if live_cert.get("sha256_fingerprint"):
                    print(f"      • SHA-256 Fingerprint : {live_cert.get('sha256_fingerprint')}")
            if certs:
                print(f"      • Certificate Transparency Logs: {len(certs)} records indexed across Certspotter & CRT.sh")

        # 10. Perimeter Gateways & Remote Access
        gateways = data.get("perimeter_gateways", [])
        if gateways and isinstance(gateways, list):
            print(f"\n  • Perimeter Gateways & Remote Access Portals (gateways.csv):")
            for g in gateways:
                print(f"      • [{g.get('vendor')}] {g.get('product')} on {g.get('host')} (HTTP {g.get('status')} · {g.get('url')})")

        # 11. Subdomain Takeover Risks
        takeovers = data.get("takeovers", [])
        if takeovers and isinstance(takeovers, list):
            print(f"\n  • Dangling DNS & Subdomain Takeover Risks (takeovers.csv):")
            for t in takeovers:
                print(f"      • [HIGH RISK] {t.get('subdomain')} -> {t.get('cname')} ({t.get('provider')})")

        # 12. Cloud Storage Exposures
        if "cloud_buckets" in data and isinstance(data.get("cloud_buckets"), list):
            buckets = data.get("cloud_buckets", [])
            if buckets:
                print(f"\n  • Discovered Cloud Storage Buckets (cloud_buckets.csv):")
                for b in buckets:
                    print(f"      • [{b.get('access')}] {b.get('name')} ({b.get('provider')}) — {b.get('url')}")
            else:
                print(f"\n  • Cloud Storage Permutation Audit (cloud_buckets.csv):")
                print(f"      • Audited AWS S3, Azure Blob, and GCP permutations — 0 exposed buckets detected.")

        # 13. Security Headers Posture
        sec_headers = data.get("security_headers", [])
        if sec_headers and isinstance(sec_headers, list):
            grades = [h.get("grade", "F") for h in sec_headers]
            print(f"\n  • HTTP Security Headers & Transport Posture (security_headers.csv):")
            print(f"      • Audited {len(sec_headers)} live host(s) — Grades: {', '.join(f'{g}: {grades.count(g)}' for g in sorted(set(grades)))}")

        # 14. Correlated Vulnerabilities & CVE Advisories
        vulns = data.get("vulnerabilities", [])
        if vulns and isinstance(vulns, list):
            print(f"\n  • Correlated Vulnerabilities & CVE Advisories (vulnerabilities.csv):")
            for v in vulns[:5]:
                cisa_tag = " [CISA KEV]" if v.get("cisa_kev") else ""
                print(f"      • [{v.get('severity')}] {v.get('cve')}{cisa_tag} — {v.get('title')} ({v.get('technology')})")
            if len(vulns) > 5:
                print(f"      • ... and {len(vulns) - 5} more advisories; see vulnerabilities.csv")

        # 15. Unmasked Origin Backend IPs
        origins = data.get("origin_ips", [])
        if origins and isinstance(origins, list):
            print(f"\n  • Unmasked Origin Backend IPs (origin_ips.csv):")
            for o in origins[:4]:
                print(f"      • [{o.get('confidence')} Confidence] {o.get('ip')} bypassing {o.get('fronted_by_cdn')} — {o.get('evidence')}")

        # 16. Autonomous Systems & BGP Routing Netblocks
        asns = data.get("asn_ranges", [])
        if asns and isinstance(asns, list):
            print(f"\n  • Autonomous Systems (ASNs) & BGP Routing Blocks (asn_ranges.csv):")
            for a in asns[:5]:
                print(f"      • {a.get('asn')} ({a.get('cidr')}) — {a.get('asn_name', a.get('description', 'Unknown'))} ({a.get('country')})")

        # 17. Active Directory & NTLM Identity Disclosures
        ntlm_items = data.get("ntlm_disclosure", [])
        if ntlm_items and isinstance(ntlm_items, list):
            print(f"\n  • Active Directory & Internal Identity Disclosures:")
            for n in ntlm_items[:3]:
                dom = n.get("dns_domain_name") or n.get("netbios_domain_name", "Unknown")
                srv = n.get("dns_computer_name") or n.get("netbios_computer_name", "Unknown")
                print(f"      • Domain: {dom} | Server: {srv} | OS: {n.get('os_version', 'Windows')} ({n.get('url')})")

        # 18. GitHub Organization OSINT
        gh = data.get("github_intel", {})
        if gh and isinstance(gh, dict) and gh.get("org"):
            sens = len(gh.get("sensitive_repos", []))
            print(f"\n  • GitHub Organization Intelligence ({gh.get('org')}):")
            print(f"      • {gh.get('public_repos', 0)} public repos, {sens} sensitive infra/devops repos identified.")

    elif mode == "username":
        results = data.get("results", [])
        breaches = data.get("breaches", [])
        checked = data.get("checked_candidate_count", 0)
        print(f"\n  • Verified Identity Findings (username_profiles.csv):")
        print(f"      • {len(results)} strictly verified profiles confirmed out of {checked} candidates.")
        for r in results[:8]:
            sources = ", ".join(r.get("sources", [r.get("source", "")]))
            print(f"      • [{r.get('platform', 'Platform')}] {r.get('url')} (HTTP {r.get('http_status', 200)} · {sources})")
        if len(results) > 8:
            print(f"      • ... and {len(results) - 8} more verified profiles.")

        if breaches:
            print(f"\n  • Breach Intelligence (breaches.csv):")
            print(f"      • {len(breaches)} breach records identified on HaveIBeenPwned:")
            for b in breaches[:5]:
                print(f"      • {b.get('title', b.get('name'))} ({b.get('domain')}) · Breach: {b.get('breach_date')} · Compromised: {b.get('pwn_count', 0):,} accounts")
            if len(breaches) > 5:
                print(f"      • ... and {len(breaches) - 5} more breach records.")

    elif mode == "person":
        results = data.get("results", [])
        dorks = data.get("dork_links", {})
        print(f"\n  • Filtered Person OSINT Results:")
        print(f"      • {len(results)} filtered public search results matching all criteria.")
        for r in results[:5]:
            print(f"      • {r.get('title', '')} — {r.get('url', '')}")
        if dorks:
            print(f"\n  • Pre-Calculated Google Dork Links (Direct Browser Access):")
            for label, url in dorks.items():
                print(f"      • [{label}] {url}")

    print("\n" + "=" * 76)
    print("#### Output Artifacts Saved To:")
    print("=" * 76)
    print(f"  • Destination Directory      : {os.path.abspath(out_dir)}")
    if h_path:
        print(f"  • Interactive HTML Dashboard : file://{os.path.abspath(h_path)}")
        print(f"                                 (Click or Ctrl+Click link above to view in browser)")
    if m_path:
        print(f"  • Executive Markdown Report  : {os.path.abspath(m_path)}")
    if j_path:
        print(f"  • Complete JSON Dataset      : {os.path.abspath(j_path)}")
    if csvs:
        print(f"  • CSV Tables ({len(csvs)})          : {', '.join(os.path.basename(c) for c in csvs)}")
    try:
        pipeline_files = [f for f in os.listdir(out_dir) if f in ("targets_nuclei.txt", "targets_web.txt", "targets_services.txt", "burp_scope.json")]
        if pipeline_files:
            print(f"  • Tool Pipeline & Scopes     : {', '.join(sorted(pipeline_files))}")
        cat_files = [f for f in os.listdir(out_dir) if (f.endswith(".txt") or (f.endswith(".json") and f != "findings.json")) and f not in pipeline_files]
        if cat_files:
            print(f"  • Category Artifacts         : {', '.join(sorted(cat_files))}")
    except Exception:
        pass
    print("=" * 76 + "\n")

def parse_formats(fmt_input: str | list[str] | None) -> set[str]:
    """Parse format input into a set of normalized format keys.
    If no format argument is specified, default is 'txt' and HTML is included in every output.
    """
    if not fmt_input:
        return {"txt", "html"}
    if isinstance(fmt_input, list):
        fmt_str = ",".join(fmt_input)
    else:
        fmt_str = str(fmt_input)

    parts = {x.strip().lower() for x in fmt_str.split(",") if x.strip()}
    if not parts:
        return {"txt", "html"}
    if "all" in parts:
        return {"all", "txt", "csv", "json", "html", "md"}

    mapped = set()
    for p in parts:
        if p in ("md", "markdown"):
            mapped.add("md")
        elif p in ("htm", "html"):
            mapped.add("html")
        elif p in ("csv", "txt", "json"):
            mapped.add(p)
        elif p == "all":
            return {"all", "txt", "csv", "json", "html", "md"}

    # HTML is always included by default with every output for web view
    mapped.add("html")
    return mapped

def _write(findings: Findings, output_format: str = "txt", webhook_url: str | None = None) -> None:
    fmts = parse_formats(output_format)
    out = _make_out_dir(findings.mode, findings.target)

    j = ""
    m = ""
    h = ""
    csvs = []

    if "all" in fmts or "json" in fmts:
        j = findings.write_json(out)
    if "all" in fmts or "md" in fmts:
        m = findings.write_markdown(out)
    if "all" in fmts or "html" in fmts:
        h = findings.write_html(out)
    if "all" in fmts or "csv" in fmts:
        csvs = findings.write_csv(out)
    if "all" in fmts or "txt" in fmts or "json" in fmts:
        findings.write_category_files(out, formats=fmts)

    # Tool Pipeline Target Exports (targets_nuclei.txt, burp_scope.json, etc.)
    try:
        from reconx.core.pipeline_export import export_pipeline_targets
        export_pipeline_targets(out, findings)
    except Exception:
        pass

    # Webhook Notification Alerts
    try:
        from reconx.core.notifications import send_scan_notification
        send_scan_notification(findings, out, webhook_url=webhook_url)
    except Exception:
        pass

    _print_executive_conclusion(findings, out, m, j, csvs, h)

def _apply_global_flags(args: argparse.Namespace) -> None:
    if getattr(args, "proxy", None):
        os.environ["RECONX_PROXY"] = args.proxy
    if getattr(args, "no_cache", False):
        os.environ["RECONX_CACHE"] = "0"
    if getattr(args, "threads", None):
        os.environ["RECONX_CONCURRENCY"] = str(args.threads)

def cmd_check(args: argparse.Namespace) -> None:
    _apply_global_flags(args)
    print_status_report()

def cmd_serve(args: argparse.Namespace) -> None:
    _apply_global_flags(args)
    from reconx.web.server import run_web_server
    run_web_server(host=getattr(args, "host", "127.0.0.1"), port=getattr(args, "port", 8080))

def cmd_domain(args: argparse.Namespace) -> None:
    _apply_global_flags(args)
    from reconx.utils.logger import banner
    banner(args.target, "domain", getattr(args, "threads", 8), getattr(args, "proxy", "") or os.environ.get("RECONX_PROXY", ""))
    from reconx.modules.domain import run_domain_recon
    findings = run_domain_recon(
        args.target,
        active=args.active,
        deep=args.deep,
        vhosts=args.vhosts,
        vhost_wordlist=args.vhost_wordlist,
        ptr_sweep=args.ptr_sweep,
        takeovers=getattr(args, "takeovers", False),
        buckets=getattr(args, "buckets", False),
        security_headers=getattr(args, "security_headers", False),
    )
    _write(findings, getattr(args, "output_format", "txt"), webhook_url=getattr(args, "webhook", None))

def cmd_username(args: argparse.Namespace) -> None:
    _apply_global_flags(args)
    from reconx.utils.logger import banner
    banner(args.target, "username", getattr(args, "threads", 8), getattr(args, "proxy", "") or os.environ.get("RECONX_PROXY", ""))
    from reconx.modules.username import enumerate_username
    result = enumerate_username(args.target)
    f = Findings(args.target, "username")
    for k, v in result.items():
        f.add(k, v)
    _write(f, getattr(args, "output_format", "txt"), webhook_url=getattr(args, "webhook", None))

def cmd_person(args: argparse.Namespace) -> None:
    _apply_global_flags(args)
    from reconx.utils.logger import banner
    banner(args.target, "person", getattr(args, "threads", 8), getattr(args, "proxy", "") or os.environ.get("RECONX_PROXY", ""))
    from reconx.modules.person import enumerate_person
    filters = {
        "location": args.location,
        "organization": args.organization,
        "keywords": args.keyword or [],
        "exclude": args.exclude or [],
        "max_results": args.max_results,
    }
    result = enumerate_person(args.target, filters)
    f = Findings(args.target, "person")
    for k, v in result.items():
        f.add(k, v)
    _write(f, getattr(args, "output_format", "txt"), webhook_url=getattr(args, "webhook", None))

def cmd_watch(args: argparse.Namespace) -> None:
    _apply_global_flags(args)
    from reconx.modules.domain.certstream_watch import watch_certstream
    try:
        asyncio.run(watch_certstream(
            args.target,
            timeout=args.timeout,
            max_matches=args.max_matches,
        ))
    except KeyboardInterrupt:
        info("\nCertStream monitoring stopped by user.")

HELP_EPILOG = """
subcommands & arguments:
  check
    Show Python tools, optional binaries, proxy configuration and API provider readiness

  domain <target> [flags]
    target                 Target domain name, e.g. example.com (enumerates subdomains, DNS, Shodan/Censys open ports, M365 & SEG)
    --active               Probe hosts over HTTP/HTTPS, collect TLS SANs, document metadata, tracking codes & perimeter gateways (GlobalProtect, Citrix, Fortinet, Cisco)
    --deep                 Also run installed passive subfinder/amass tools
    --vhosts               Check bounded HTTP Host-header virtual-host candidates against baseline
    --vhost-wordlist PATH  Path to custom vhost wordlist (one label per line, up to 500 labels)
    --ptr-sweep            Perform bounded reverse-DNS (PTR) sweep on discovered IPs
    --takeovers            Audit subdomains for dangling CNAME pointers and cloud service takeover risks
    --buckets              Audit organizational cloud storage bucket naming permutations across AWS, Azure, and GCP
    --security-headers     Audit HTTP security headers (CSP, HSTS, XFO) and defensive hygiene on live hosts

  username <target>
    target                 Username handle to investigate, e.g. analyst123

  person "<target>" [flags]
    target                 Full name in quotes, e.g. "Jane Example"
    --location LOC         Required location phrase to filter results
    --organization ORG     Organization/company filter
    --keyword KW           Include results containing at least one keyword (repeatable)
    --exclude TERM         Exclude results containing a term (repeatable)
    --max-results N        Maximum filtered results (1–50; default: 20)

  watch <target> [flags]
    target                 Target domain to monitor on CertStream, e.g. example.com
    --timeout SECS         Stop watching after N seconds (default: run until interrupted)
    --max-matches N        Stop after finding N matching certificates

### Quick Usage Cheatsheet:

  # 1. Environment & readiness check
  reconx check

  # 2. Fast passive domain recon (CRT.sh, DNS, RDAP/WHOIS, Shodan/Censys open ports, Wayback CDX, M365 & SEG Audit)
  reconx domain example.com

  # 3. Full red-team attack surface sweep (Active HTTP, TLS SANs, Gateways/VPNs, JS endpoints, Vhosts, PTR sweep)
  reconx domain example.com --deep --active --vhosts --ptr-sweep

  # 4. Red-team cloud audit (Dangling CNAME takeovers, S3/Azure/GCP storage buckets, HTTP security headers)
  reconx domain example.com --active --takeovers --buckets --security-headers

  # 5. Route entire scan through Tor (OPSEC)
  reconx domain example.com --active --proxy socks5://127.0.0.1:9050

  # 6. Live Certificate Transparency monitoring (watch for new subdomains in real time)
  reconx watch example.com

  # 7. Username recon with WhatsMyName, Sherlock, and HaveIBeenPwned breach intel
  reconx username targetuser

  # 8. Targeted person OSINT with strict filters & Google Dork links
  reconx person "Jane Example" --location "London, UK" --organization "Target Labs" --keyword security

  # 9. High-performance multi-threaded sweep with 16 parallel workers
  reconx domain example.com -t 16

  # 10. Select specific output formats (HTML web view is always included by default)
  reconx domain example.com --format csv,json
  reconx domain example.com -f txt

  # 11. Launch the interactive local Web GUI & REST API server
  reconx serve --port 8080
"""

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — plugin-based, passive-first red-team reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EPILOG,
    )
    p.add_argument("--version", action="version", version="ReconX 0.3.3")
    p.add_argument("-t", "--threads", "--concurrency", type=int, default=8, help="Number of concurrent worker threads (default: 8)")
    p.add_argument("-f", "--format", dest="output_format", default="txt", help="Output format(s): txt, csv, json, md, or all (default: txt; HTML is always included in every output)")
    p.add_argument("--proxy", help="Route HTTP/HTTPS requests through a proxy, e.g. socks5://127.0.0.1:9050 or http://127.0.0.1:8080")
    p.add_argument("--webhook", help="Webhook URL for Discord, Slack, or generic webhook scan alerts")
    p.add_argument("--no-cache", action="store_true", help="Bypass local SQLite request cache")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Show Python tools, optional binaries, proxy configuration and API provider readiness")

    srv = sub.add_parser("serve", help="Launch the local interactive Web GUI & REST API dashboard")
    srv.add_argument("--host", default="127.0.0.1", help="Binding interface host (default: 127.0.0.1)")
    srv.add_argument("--port", type=int, default=8080, help="Listening port (default: 8080)")

    d = sub.add_parser("domain", help="Passive domain attack-surface, M365 identity & email security recon; bounded HTTP/TLS checks are opt-in")
    d.add_argument("target", help="Domain name, e.g. example.com")
    d.add_argument("-t", "--threads", "--concurrency", type=int, default=8, help="Number of concurrent worker threads (default: 8)")
    d.add_argument("-f", "--format", dest="output_format", default="txt", help="Output format(s): txt, csv, json, md, or all (default: txt; HTML is always included in every output)")
    d.add_argument("--webhook", help="Webhook URL for Discord, Slack, or generic webhook scan alerts")
    d.add_argument("--active", action="store_true", help="Probe discovered hosts over HTTP/HTTPS, collect TLS SANs, document metadata, tracking codes & perimeter gateways")
    d.add_argument("--deep", action="store_true", help="Also run installed passive subfinder/amass tools")
    d.add_argument("--vhosts", action="store_true", help="Check bounded HTTP Host-header virtual-host candidates against baseline")
    d.add_argument("--vhost-wordlist", help="Path to custom vhost wordlist (one label per line, up to 500 labels)")
    d.add_argument("--ptr-sweep", action="store_true", help="Perform bounded reverse-DNS (PTR) sweep on discovered IPs")
    d.add_argument("--takeovers", action="store_true", help="Audit subdomains for dangling CNAME pointers and cloud service takeover risks")
    d.add_argument("--buckets", action="store_true", help="Audit organizational cloud storage bucket naming permutations across AWS, Azure, and GCP")
    d.add_argument("--security-headers", action="store_true", help="Audit HTTP security headers (CSP, HSTS, XFO) and defensive hygiene on live hosts")

    u = sub.add_parser("username", help="Find username profiles; only independently verified profiles and breach intel are reported")
    u.add_argument("target", help="Username, e.g. analyst123")
    u.add_argument("-t", "--threads", "--concurrency", type=int, default=8, help="Number of concurrent worker threads (default: 8)")
    u.add_argument("-f", "--format", dest="output_format", default="txt", help="Output format(s): txt, csv, json, md, or all (default: txt; HTML is always included in every output)")

    pe = sub.add_parser("person", help="Search public web results with strict name and optional filters")
    pe.add_argument("target", help='Full name in quotes, e.g. "Jane Example"')
    pe.add_argument("-t", "--threads", "--concurrency", type=int, default=8, help="Number of concurrent worker threads (default: 8)")
    pe.add_argument("-f", "--format", dest="output_format", default="txt", help="Output format(s): txt, csv, json, md, or all (default: txt; HTML is always included in every output)")
    pe.add_argument("--location", help="Required location phrase to filter results")
    pe.add_argument("--organization", help="Organization/company filter")
    pe.add_argument("--keyword", action="append", help="Include results containing at least one keyword (repeatable)")
    pe.add_argument("--exclude", action="append", help="Exclude results containing a term (repeatable)")
    pe.add_argument("--max-results", type=int, default=20, choices=range(1, 51), help="Maximum filtered results (1–50; default 20)")

    w = sub.add_parser("watch", help="Live Certificate Transparency (CertStream) monitoring for newly issued certificates")
    w.add_argument("target", help="Target domain, e.g. example.com")
    w.add_argument("--timeout", type=float, help="Stop watching after N seconds (default: run until interrupted)")
    w.add_argument("--max-matches", type=int, help="Stop after finding N matching certificates")

    return p

def main() -> None:
    p = build_parser()
    import sys
    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(0)
    a = p.parse_args()
    commands = {
        "check": cmd_check,
        "serve": cmd_serve,
        "domain": cmd_domain,
        "username": cmd_username,
        "person": cmd_person,
        "watch": cmd_watch,
    }
    commands[a.command](a)

if __name__ == "__main__":
    main()
